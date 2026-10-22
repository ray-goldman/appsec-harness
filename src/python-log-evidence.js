'use strict';
const ASSIGNMENTS = new Set(['=', ':=', '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '<<=', '>>=', '**=', '//=', '@=']);

function sourceLines(code) {
  const starts = [0];
  for (let i = 0; i < code.length; i++) if (code[i] === '\n') starts.push(i + 1);
  return { starts, lines: code.split('\n'), at(offset) {
    let lo = 0, hi = starts.length;
    while (lo + 1 < hi) { const mid = (lo + hi) >>> 1; if (starts[mid] <= offset) lo = mid; else hi = mid; }
    return lo;
  } };
}

// Bounded lexical evidence only. No Python runtime, imports or target execution.
function tokenize(code) {
  if (Buffer.byteLength(code, 'utf8') > 200000 || /\r(?!\n)|[\u0000\u000b\u000c]/.test(code)) return null;
  const tokens = [], brackets = [];
  let i = 0;
  function string(start, quoteAt, prefix, depth = 0) {
    if (depth > 64) throw Error('string nesting');
    const quote = code[quoteAt], triple = code.startsWith(quote.repeat(3), quoteAt);
    const delimiter = triple ? quote.repeat(3) : quote, bodyStart = quoteAt + delimiter.length;
    const formatted = /f/i.test(prefix);
    let k = bodyStart, escaped = false;
    while (k < code.length) {
      if (code[k] === '\\') { escaped = true; k += 2; continue; }
      if (code.startsWith(delimiter, k)) return { kind: 'string', start, end: k + delimiter.length, prefix, triple, escaped, value: code.slice(bodyStart, k) };
      if (!triple && /[\r\n]/.test(code[k])) throw Error('unterminated string');
      if (formatted && code[k] === '{') {
        if (code[k + 1] === '{') { k += 2; continue; }
        let balance = 1; k++;
        while (k < code.length && balance) {
          if (code[k] === '"' || code[k] === "'") {
            if (/[A-Za-z0-9_]/.test(code[k - 1] || '') || code[k] === quote) throw Error('unsupported nested format string');
            k = string(k, k, '', depth + 1).end; continue;
          }
          if (code[k] === '{') { if (++balance > 64) throw Error('format nesting'); }
          if (code[k] === '}') balance--;
          k++;
        }
        if (balance) throw Error('unterminated format');
        continue;
      }
      k++;
    }
    throw Error('unterminated string');
  }
  try {
    while (i < code.length) {
      if (tokens.length >= 50000) return null;
      const start = i, ch = code[i];
      if (ch === ' ' || ch === '\t' || ch === '\r') { i++; continue; }
      if (ch === '#') { while (i < code.length && code[i] !== '\n') i++; continue; }
      if (ch === '\n') { tokens.push({ kind: 'newline', value: '\n', start, end: ++i }); continue; }
      if (ch === '"' || ch === "'") { const token = string(start, start, ''); tokens.push(token); i = token.end; continue; }
      if (/[A-Za-z_]/.test(ch)) {
        while (i < code.length && /[A-Za-z0-9_]/.test(code[i])) i++;
        const value = code.slice(start, i);
        if (code[i] === '"' || code[i] === "'") {
          if (!/^(?:r|u|b|f|fr|rf|br|rb)$/i.test(value)) return null;
          const token = string(start, i, value); tokens.push(token); i = token.end;
        } else tokens.push({ kind: 'id', value, start, end: i });
        continue;
      }
      if (/[0-9]/.test(ch)) {
        while (i < code.length && /[A-Za-z0-9_.]/.test(code[i])) i++;
        tokens.push({ kind: 'number', value: code.slice(start, i), start, end: i }); continue;
      }
      if (ch === '\\') return null; // explicit continuations are outside this subset
      if (ch.charCodeAt(0) > 127 || ch.charCodeAt(0) < 32) return null;
      if ('([{'.includes(ch)) { brackets.push(ch); if (brackets.length > 64) return null; }
      if (')]}'.includes(ch) && brackets.pop() !== { ')': '(', ']': '[', '}': '{' }[ch]) return null;
      const pair = code.slice(i, i + 2);
      const triple = code.slice(i, i + 3);
      const value = ['<<=', '>>=', '**=', '//='].includes(triple) ? triple :
        ['==', '!=', '>=', '<=', ':=', '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '@=', '**', '//', '->'].includes(pair) ? pair : ch;
      i += value.length; tokens.push({ kind: 'op', value, start, end: i });
    }
    return brackets.length ? null : tokens;
  } catch { return null; }
}

function logicalStatements(tokens) {
  const statements = [];
  let statement = [], depth = 0;
  for (const token of tokens) {
    if ((token.kind === 'newline' || token.value === ';' && token.kind === 'op') && !depth) {
      if (statement.length) statements.push(statement);
      statement = []; continue;
    }
    if (token.kind === 'newline') continue;
    statement.push(token);
    if (token.kind === 'op' && '([{'.includes(token.value)) depth++;
    if (token.kind === 'op' && ')]}'.includes(token.value)) depth--;
  }
  if (statement.length) statements.push(statement);
  return statements;
}

function pythonAuthCode(code) {
  const tokens = tokenize(code);
  if (!tokens || /\b(?:exec|eval|compile|getattr|setattr|globals|locals|vars|__doc__|__dict__|__globals__|__getattribute__)\b/.test(code)) return code;
  const out = code.split('');
  const locations = sourceLines(code), statements = logicalStatements(tokens);
  for (let n = 0; n < statements.length; n++) {
    if (statements[n].length !== 1) continue;
    const token = statements[n][0];
    if (token.kind !== 'string' || token.prefix || !token.triple || token.escaped) continue;
    const startLine = locations.at(token.start), endLine = locations.at(token.end);
    const indent = code.slice(locations.starts[startLine], token.start);
    if (!/^ *$/.test(indent) || !/^\s*$/.test(code.slice(token.end, locations.starts[endLine + 1] ?? code.length))) continue;
    let doc = n === 0 && !indent.length;
    const previous = statements[n - 1];
    const header = previous ? locations.lines[locations.at(previous[0].start)] : '';
    const headerIndent = header.match(/^ */)[0].length;
    if (/^ *(?:async +)?def +[A-Za-z_]\w*\s*\(/.test(header) && /:\s*$/.test(header) &&
        headerIndent === 0 && indent.length > headerIndent && statements[n - 2]?.[0]?.value !== '@') doc = true;
    if (doc) for (let k = token.start; k < token.end; k++) if (!/[\r\n]/.test(out[k])) out[k] = ' ';
  }
  return out.join('');
}

function requestProfile(code, tokens, project) {
  if (!project?.indexedComplete || !project.entries || [...project.entries.keys()].some(file => /(?:^|\/)flask(?:\.py|\/)/i.test(file))) return false;
  if (/\b(?:exec|eval|compile|setattr|globals|locals|vars|__dict__|__globals__|__builtins__|__getattribute__|REMOTE_ADDR|request_class|wsgi_app)\b/.test(code)) return false;
  if (tokens.some(t => t.kind === 'string' && /f/i.test(t.prefix) && /\brequest\b/.test(t.value))) return false;
  const ids = tokens.filter(t => t.kind !== 'newline'), imported = new Set();
  const unsafeTail = new Map();
  for (const statement of logicalStatements(tokens)) {
    let unsafe = ['with', 'del'].includes(statement[0]?.value) || statement[0]?.value === 'async' && statement[1]?.value === 'with';
    for (let i = statement.length - 1; i >= 0; i--) {
      const token = statement[i];
      unsafeTail.set(token, unsafe);
      if (token.kind === 'op' && ASSIGNMENTS.has(token.value) || token.kind === 'id' && token.value === 'in') unsafe = true;
    }
  }
  let imports = 0;
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i].value === 'import' && tokens[i + 1]?.value === '*') return false;
    if (tokens[i].kind !== 'id' || tokens[i].value !== 'from' || tokens[i + 1]?.kind !== 'id' || tokens[i + 1]?.value !== 'flask' || tokens[i + 2]?.kind !== 'id' || tokens[i + 2]?.value !== 'import') continue;
    let j = i + 3;
    let expectName = true;
    for (; j < tokens.length && tokens[j].kind !== 'newline'; j++) {
      if (expectName ? tokens[j].kind !== 'id' || ['as', 'import', 'from'].includes(tokens[j].value) : tokens[j].value !== ',') return false;
      if (tokens[j].kind === 'id' && tokens[j].value === 'request') { imported.add(tokens[j]); imports++; }
      expectName = !expectName;
    }
  }
  if (imports !== 1) return false;
  const fields = new Set(['path', 'method', 'form', 'remote_addr', 'endpoint', 'headers', 'args', 'get_json', 'files', 'cookies', 'json', 'data']);
  for (let i = 0; i < ids.length; i++) {
    if (ids[i].kind === 'id' && /Request$/.test(ids[i].value)) return false;
    if (ids[i].kind === 'id' && ids[i].value === 'remote_addr') {
      if (ids[i - 1]?.value !== '.' || ids[i - 2]?.value !== 'request') return false;
      if (unsafeTail.get(ids[i])) return false;
    }
    if (ids[i].value !== 'request' || imported.has(ids[i])) continue;
    if (ids[i].kind !== 'id' || ids[i - 1]?.value === 'del' || ids[i + 1]?.value !== '.' || !fields.has(ids[i + 2]?.value)) return false;
    let j = i + 3;
    if (ASSIGNMENTS.has(ids[j]?.value)) return false;
  }
  return true;
}

function createPythonLoggingProof(code, project) {
  let analysis;
  return line => {
    if (analysis === undefined) {
      const tokens = tokenize(code);
      analysis = new Map();
      if (!tokens) return false;
      const locations = sourceLines(code);
      const profile = requestProfile(code, tokens, project);
      for (const token of tokens) if (token.kind === 'string' && /f/i.test(token.prefix)) {
        for (let n = locations.at(token.start); n <= locations.at(token.end); n++) {
          if (!analysis.has(n)) analysis.set(n, []);
          analysis.get(n).push(false);
        }
      }
      for (let i = 0; i < tokens.length; i++) {
        const token = tokens[i];
        if (token.kind !== 'id' || !/^(?:logger|logging|log|print)(?:info|debug|warning|error|critical|exception)?$/i.test(token.value)) continue;
        let open = i + 1;
        if (tokens[open]?.value === '.') open += 2;
        if (tokens[open]?.value !== '(') continue;
        let depth = 1, end = open + 1;
        const args = [[]];
        for (; end < tokens.length && depth; end++) {
          const current = tokens[end];
          if ('([{'.includes(current.value) && current.kind === 'op') depth++;
          if (')]}'.includes(current.value) && current.kind === 'op') depth--;
          if (!depth) break;
          if (current.kind === 'newline') continue;
          if (current.value === ',' && depth === 1) args.push([]); else args.at(-1).push(current);
        }
        let safe = false;
        const message = args[0]?.length === 1 && args[0][0].kind === 'string' && !args[0][0].prefix && !args[0][0].triple && !args[0][0].escaped ? args[0][0].value : null;
        if (message !== null && /^(?:Initial )?(?:(?:Account|Dashboard|User|Service|Application|UI|API|dashboard|account|user|service|application) )?(?:Password|password|Token|token|Secret|secret) (?:changed|configured|created|updated|rotated|reset)(?: from %s)?[.!]?$/u.test(message)) {
          safe = args.length === 1 && !message.includes('%');
          if (profile && / from %s[.!]?$/.test(message) && args.length === 2) {
            const parts = args[1];
            safe = parts.length === 3 && parts.map(t => t.value).join('') === 'request.remote_addr' ||
              parts.length === 5 && parts.slice(0, 4).map(t => t.value).join('') === 'request.remote_addror' &&
              parts[4].kind === 'string' && !parts[4].prefix && !parts[4].escaped && parts[4].value === 'unknown';
          }
        }
        const first = locations.at(token.start);
        const last = locations.at(tokens[end]?.end ?? code.length);
        for (let n = first; n <= last; n++) {
          if (!analysis.has(n)) analysis.set(n, []);
          analysis.get(n).push(safe);
        }
      }
    }
    const calls = analysis.get(line);
    return !!calls?.length && calls.every(Boolean);
  };
}

module.exports = { pythonAuthCode, createPythonLoggingProof };
