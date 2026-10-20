'use strict';

// A deliberately small, non-executing PHP lexer. Keeping string tokens intact is
// essential: stream names are data, whereas calls and aliases are executable syntax.
function tokenize(code) {
  const tokens = [];
  let i = 0, line = 1, col = 1;
  const hasTags = /<\?(?:php\b|=)/i.test(code);
  let inPhp = !hasTags;
  const advance = (end) => { while (i < end) { if (code[i++] === '\n') { line++; col = 1; } else col++; } };
  while (i < code.length) {
    if (!inPhp) {
      const tag = /<\?(?:php\b|=)/ig;
      tag.lastIndex = i;
      const found = tag.exec(code);
      if (!found) break;
      advance(found.index + found[0].length); inPhp = true; continue;
    }
    if (hasTags && code.startsWith('?>', i)) { advance(i + 2); inPhp = false; continue; }
    if (/\s/.test(code[i])) { advance(i + 1); continue; }
    if (code.startsWith('//', i) || code[i] === '#') {
      const end = code.indexOf('\n', i); advance(end < 0 ? code.length : end); continue;
    }
    if (code.startsWith('/*', i)) {
      const end = code.indexOf('*/', i + 2); advance(end < 0 ? code.length : end + 2); continue;
    }
    const start = i, token = { line, col, start };
    const heredoc = code.startsWith('<<<', i) && code.slice(i).match(/^<<<[ \t]*(?:(['"])(\w+)\1|(\w+))[ \t]*\r?\n/);
    if (heredoc) {
      const contentStart = i + heredoc[0].length;
      const closing = new RegExp('^[ \\t]*' + (heredoc[2] || heredoc[3]) + '(?=[;\\r\\n])', 'gm');
      closing.lastIndex = contentStart;
      const found = closing.exec(code);
      token.type = 'string'; token.quote = heredoc[1] === "'" ? "'" : '"';
      token.value = code.slice(contentStart, found ? found.index : code.length);
      advance(found ? found.index + found[0].length : code.length);
    } else if (code[i] === "'" || code[i] === '"' || code[i] === '`') {
      const quote = code[i];
      let end = i + 1;
      while (end < code.length) {
        if (code[end] === '\\') { end += 2; continue; }
        if (code[end++] === quote) break;
      }
      token.type = 'string'; token.quote = quote;
      token.value = code.slice(i + 1, end - 1);
      advance(Math.min(end, code.length));
    } else {
      const match = code.slice(i).match(/^(?:\$[a-zA-Z_\x80-\xff][\w\x80-\xff]*|[a-zA-Z_\x80-\xff][\w\x80-\xff]*|[0-9]+|->|\?->|::|=>|\.=|===|!==|==|!=|&&|\|\|)/);
      token.value = match ? match[0] : code[i];
      token.type = token.value[0] === '$' ? 'variable' : /^[a-zA-Z_]/.test(token.value) ? 'word' : 'symbol';
      advance(i + token.value.length);
    }
    token.end = i;
    tokens.push(token);
  }
  const stack = [];
  for (let n = 0; n < tokens.length; n++) {
    const value = tokens[n].value;
    if (tokens[n].type === 'string') continue;
    if (['(', '[', '{'].includes(value)) stack.push(n);
    if ([')', ']', '}'].includes(value)) {
      const open = stack.pop();
      if (open !== undefined) { tokens[open].close = n; tokens[n].open = open; }
    }
  }
  return tokens;
}

const REQUEST = /^\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)$/;
const UNKNOWN = Object.freeze({ unknown: true });
// Constant folding is only a proof aid. Cap retained text so a loop repeatedly
// concatenating a value cannot grow analyzer memory exponentially.
const literal = (value) => typeof value === 'string' && value.length > 4096 ? UNKNOWN : ({ constant: value });
function merge(a, b) {
  if (a.entries || b.entries) {
    const baseA = a.base || a, baseB = b.base || b;
    const entries = new Map();
    for (const key of new Set([...(a.entries?.keys() || []), ...(b.entries?.keys() || [])])) {
      entries.set(key, merge(a.entries?.get(key) || baseA, b.entries?.get(key) || baseB));
    }
    return { entries, base: merge(baseA, baseB) };
  }
  if (a.source) return a;
  if (b.source) return b;
  return a.unknown || b.unknown ? UNKNOWN : literal(undefined);
}
function argsOf(tokens, open) {
  const end = tokens[open].close;
  if (end === undefined) return [];
  const args = [];
  let start = open + 1;
  for (let i = start; i < end; i++) {
    if (tokens[i].value === ',' && tokens[i].type !== 'string') { args.push([start, i]); start = i + 1; }
    else if (tokens[i].close !== undefined) i = tokens[i].close;
  }
  args.push([start, end]);
  return args;
}

function checkPhpCode({ raw, code, maxReplayTokens }) {
  const tokens = tokenize(raw === undefined ? code : raw);
  let env = new Map();
  const frames = [], braces = [];
  let pendingFunction = false, pendingConditional = false, pendingLoop = false, replayedTokens = 0;
  const out = [];
  const replayBudget = Number.isInteger(maxReplayTokens) && maxReplayTokens >= 0
    ? Math.min(maxReplayTokens, 100000) : Math.min(100000, tokens.length * 8 + 4096);
  const hasNamespace = tokens.some((t) => t.type === 'word' && t.value.toLowerCase() === 'namespace');
  const hasFunctionImports = tokens.some((t, i) => t.value.toLowerCase() === 'use' && tokens[i + 1]?.value.toLowerCase() === 'function');
  const functionDefinition = (i) => {
    let next = i + 1;
    if (tokens[next]?.value === '&') next++;
    return tokens[next]?.value === '(' || (tokens[next]?.type === 'word' && tokens[next + 1]?.value === '(');
  };
  const declarations = new Set();
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i].value.toLowerCase() === 'function' && functionDefinition(i)) {
      const name = tokens[i + 1]?.value === '&' ? tokens[i + 2] : tokens[i + 1];
      if (name?.type === 'word') declarations.add(name.value.toLowerCase());
    }
  }
  function builtinAt(i) {
    if (['->', '?->', '::'].includes(tokens[i - 1]?.value)) return false;
    if (tokens[i - 1]?.value === '\\') return tokens[i - 2]?.type !== 'word' && tokens[i - 2]?.value !== '\\';
    return !hasNamespace && !hasFunctionImports && !declarations.has(tokens[i].value.toLowerCase());
  }
  function loopState(block, values) {
    return JSON.stringify([...block.writes].sort().map((key) => [key, values.get(key) || UNKNOWN]),
      (_key, value) => value instanceof Map ? [...value.entries()].sort(([a], [b]) => a.localeCompare(b)) : value);
  }

  const variable = (name, token) => REQUEST.test(name)
    ? { source: name, line: token.line }
    : env.get(name) || UNKNOWN;

  function expression(start, end, depth = 0) {
    if (depth > 64 || start >= end) return UNKNOWN;
    if (tokens[start].value === '(' && tokens[start].close === end - 1) return expression(start + 1, end - 1, depth + 1);
    if (/^(?:function|fn)$/i.test(tokens[start].value) ||
        (tokens[start].value === 'static' && /^(?:function|fn)$/i.test(tokens[start + 1]?.value || ''))) return literal(undefined);
    const top = [];
    for (let i = start; i < end; i++) {
      if (tokens[i].close !== undefined) i = tokens[i].close;
      else if (tokens[i].type !== 'string') top.push(i);
    }
    const question = top.find((i) => tokens[i].value === '?');
    if (question !== undefined) {
      let nested = 0, colon;
      for (const i of top.filter((i) => i > question)) {
        if (tokens[i].value === '?') nested++;
        if (tokens[i].value === ':' && nested-- === 0) { colon = i; break; }
      }
      if (colon !== undefined) return merge(
        expression(question + 1 === colon ? start : question + 1, colon, depth + 1),
        expression(colon + 1, end, depth + 1),
      );
    }
    // Booleans and numeric results cannot carry arbitrary PHP text. Split
    // concatenation first when interpreting casts so an unsafe suffix survives.
    if (top.some((i) => /^(?:===|!==|==|!=|<|>|&&|\|\||and|or|xor)$/i.test(tokens[i].value))) return literal(undefined);
    const dots = top.filter((i) => tokens[i].value === '.');
    if (dots.length) {
      let value = literal(''), last = start;
      for (const dot of [...dots, end]) {
        const part = expression(last, dot, depth + 1);
        value = typeof value.constant === 'string' && typeof part.constant === 'string'
          ? literal(value.constant + part.constant) : merge(value, part);
        last = dot + 1;
      }
      return value;
    }
    if (tokens[start].value === '(' && tokens[start].close === start + 2 &&
        /^(?:int|integer|float|double|real|bool|boolean)$/i.test(tokens[start + 1].value)) return literal(undefined);
    if (top.some((i) => /^(?:\+|-|\*|\/|%)$/.test(tokens[i].value))) return literal(undefined);
    let value = literal(''), constant = '', onlyConstants = true;
    for (let i = start; i < end; i++) {
      const token = tokens[i];
      let next;
      if (token.type === 'string') {
        next = token.quote === '`' ? UNKNOWN : literal(token.value);
        if (token.quote !== "'") {
          // Escaped dollar signs are literal; interpolated variables carry their source.
          for (const match of token.value.matchAll(/(\\*)\$[a-zA-Z_]\w*/g)) {
            if (match[1].length % 2) continue;
            next = merge(next, variable(match[0].slice(match[1].length), token));
          }
        }
      } else if ((token.type === 'word' || token.type === 'variable') && tokens[i + 1]?.value === '(') {
        const args = argsOf(tokens, i + 1);
        const name = token.value.toLowerCase();
        if (!args.length || tokens[i + 1].close >= end) return UNKNOWN;
        const argValues = args.map(([a, b]) => expression(a, b, depth + 1));
        const builtin = builtinAt(i);
        if (builtin && /^(?:intval|floatval|boolval|strlen|count|sizeof|ord)$/.test(name)) {
          next = literal(undefined);
        } else if (builtin && ['file_get_contents', 'fopen'].includes(name) && argValues[0]?.constant?.toLowerCase() === 'php://input') {
          next = { source: 'php://input', line: token.line };
        } else if (builtin && /^(?:trim|ltrim|rtrim|substr|str_replace|base64_decode|urldecode|rawurldecode|stripslashes|stream_get_contents|fread)$/.test(name)) {
          next = argValues.reduce(merge, literal(undefined));
        } else next = UNKNOWN;
        i = tokens[i + 1].close;
      } else if (token.type === 'variable') {
        next = variable(token.value, token);
        // An index selects a value; its text does not become the selected code.
        // Request arrays still carry their source through arbitrary offsets.
        const keys = [];
        while (tokens[i + 1]?.value === '[' && tokens[i + 1].close !== undefined) {
          keys.push(expression(i + 2, tokens[i + 1].close, depth + 1).constant);
          i = tokens[i + 1].close;
        }
        if (keys.length && next.entries) {
          next = keys.every((key) => key !== undefined)
            ? next.entries.get(JSON.stringify(keys)) || next.base
            : [...next.entries.values()].reduce(merge, next.base);
        }
      } else if (token.type === 'word' && !/^(?:true|false|null)$/i.test(token.value)) {
        next = UNKNOWN;
      } else if (token.value === '.') continue;
      else { next = literal(token.value); }
      value = merge(value, next);
      if (typeof next.constant !== 'string') onlyConstants = false;
      else constant += next.constant;
    }
    return value.source || value.unknown ? value : literal(onlyConstants ? constant : undefined);
  }

  function emit(token, state, name, forceReview = false) {
    if (!state.source && !state.unknown && !forceReview) return;
    const confirmed = Boolean(state.source);
    out.push({
      line: token.line, col: token.col, kind: confirmed ? 'vulnerability' : 'review',
      confidence: confirmed ? 'high' : 'low', severity: confirmed ? 'critical' : 'low',
      taint: confirmed ? { source: state.source, line: state.line } : undefined,
      title: confirmed ? 'Request data reaches PHP code execution' : 'Dynamic PHP code execution needs review',
      message: confirmed ? 'Request-controlled data reaches a PHP code execution argument.' : 'Dynamic PHP execution is present; an attacker-controlled source has not been established.',
      detail: confirmed ? `${name}: request source ${state.source} at line ${state.line}` : `${name}: unresolved or non-HTTP input; review caller and runtime context.`,
    });
  }

  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i], name = token.value.toLowerCase();
    if (token.type === 'string') continue;
    if (name === 'function' && functionDefinition(i)) { frames.push(env); env = new Map(); pendingFunction = true; }
    if (/^(?:if|elseif|else|for|foreach|while|do|switch|catch|try)$/.test(name)) pendingConditional = true;
    if (/^(?:for|foreach|while|do)$/.test(name)) pendingLoop = true;
    if (token.value === '{') {
      braces.push({ fn: pendingFunction, before: pendingConditional && !pendingFunction ? new Map(env) : null, loop: pendingLoop, start: i, writes: new Set() });
      pendingFunction = false; pendingConditional = false; pendingLoop = false;
    }
    if (token.value === '}') {
      const block = braces.pop();
      if (block?.fn) env = frames.pop() || new Map();
      else if (block?.loop && !block.widened) {
        const state = loopState(block, env);
        const previous = block.state === undefined ? loopState(block, block.before || new Map()) : block.state;
        if (state !== previous) {
          block.state = state;
          if (replayedTokens + i - block.start <= replayBudget) {
            replayedTokens += i - block.start;
          } else {
            // Do one final pass with uncertain modified aliases. Literal writes
            // still kill taint before sinks, but unresolved loops stay visible.
            block.widened = true;
            for (const key of block.writes) if (!env.get(key)?.source) env.set(key, UNKNOWN);
          }
          braces.push(block);
          i = block.start;
          continue;
        }
      }
      if (!block?.fn && block?.before) {
        for (const [key, value] of block.before) env.set(key, merge(value, env.get(key) || UNKNOWN));
      }
    }
    let assignment = i + 1;
    const writeKeys = [];
    if (token.type === 'variable') {
      while (tokens[assignment]?.value === '[' && tokens[assignment].close !== undefined) {
        writeKeys.push(expression(assignment + 1, tokens[assignment].close).constant);
        assignment = tokens[assignment].close + 1;
      }
    }
    if (token.type === 'variable' && ['=', '.='].includes(tokens[assignment]?.value)) {
      for (let j = braces.length - 1; j >= 0 && !braces[j].fn; j--) if (braces[j].loop) braces[j].writes.add(token.value);
      let end = assignment + 1;
      while (end < tokens.length && ![';', '}'].includes(tokens[end].value)) {
        if (tokens[end].close !== undefined) end = tokens[end].close;
        end++;
      }
      const value = expression(assignment + 1, end);
      const prior = env.get(token.value) || UNKNOWN;
      if (writeKeys.length && writeKeys.every((key) => key !== undefined)) {
        const entries = new Map(prior.entries || []);
        const key = JSON.stringify(writeKeys);
        entries.set(key, pendingConditional || tokens[assignment].value === '.=' ? merge(entries.get(key) || prior.base || prior, value) : value);
        env.set(token.value, { entries, base: prior.base || prior });
      } else {
        env.set(token.value, pendingConditional || writeKeys.length || tokens[assignment].value === '.=' ? merge(prior, value) : value);
      }
    }
    if (token.value === ';') { pendingConditional = false; pendingLoop = false; }
    if (tokens[i + 1]?.value !== '(') continue;
    // Method names and function declarations are not calls to PHP's builtins.
    if (['->', '?->', '::', 'function', 'new'].includes(tokens[i - 1]?.value)) continue;
    const args = argsOf(tokens, i + 1);
    if (!args.length) continue;
    const stateAt = (arg) => args[arg] ? expression(...args[arg]) : UNKNOWN;
    if (name === 'eval') emit(token, stateAt(0), name);
    else if (['assert', 'create_function', 'preg_replace', 'call_user_func', 'call_user_func_array'].includes(name) && !builtinAt(i)) emit(token, UNKNOWN, name);
    else if (name === 'assert') emit(token, stateAt(0), name);
    else if (name === 'create_function') emit(token, stateAt(1), name, true);
    else if (name === 'preg_replace') {
      const pattern = stateAt(0).constant;
      if (pattern && /^[^\w\s\\]/.test(pattern)) {
        const close = pattern.lastIndexOf(pattern[0]);
        if (close > 0 && /^[a-z]*e[a-z]*$/i.test(pattern.slice(close + 1))) emit(token, stateAt(1), name, true);
      }
    } else if (/^call_user_func(?:_array)?$/.test(name)) emit(token, stateAt(0), name);
    else if (token.type === 'variable') {
      const callback = variable(token.value, token);
      if (callback.source) emit(token, callback, 'dynamic callback');
      else if (callback.unknown && args.some(([a, b]) => expression(a, b).source)) emit(token, UNKNOWN, 'dynamic callback');
      else if (callback.constant?.toLowerCase() === 'assert') emit(token, stateAt(0), 'assert callback');
    }
  }
  const unique = new Map();
  for (const hit of out) {
    const key = `${hit.line}:${hit.col}`;
    if (!unique.has(key) || hit.kind === 'vulnerability') unique.set(key, hit);
  }
  return [...unique.values()];
}

module.exports = { checkPhpCode };
