'use strict';
const { maskStrings } = require('./languages');
const { evaluate, excludedBranches } = require('./java-branches');
const { createJavaSummaries, isSafeFact } = require('./java-summaries');

// This is a bounded proof for local String values, not a Java parser. Unknown
// syntax retains the warning. Inspect all writes, including writes after a sink
// which could affect a later loop iteration.
function constantSinkFilter(code, callArgs, raw = code, options = {}) {
  const masked = maskStrings(code, 'java');
  if (/\\u+[0-9a-fA-F]{4}/.test(raw) || /"""|->/.test(code)) {
    const unknown = () => false;
    unknown.sqlAssembly = unknown;
    unknown.valueAt = unknown;
    return unknown;
  }
  const summaries = createJavaSummaries({ file: options.file || '<file>', raw, code, project: options.project });
  const methods = [];
  const declaration = /\b(?:void|String|boolean|int|long|Object)\s+\w+\s*\([^{};]*\)\s*(?:throws\s+[\w.,\s]+)?\{/g;
  let m;
  while ((m = declaration.exec(masked))) {
    const start = m.index + m[0].length;
    let end = start, depth = 1;
    for (; end < masked.length && depth; end++) {
      if (masked[end] === '{') depth++;
      if (masked[end] === '}') depth--;
    }
    if (!depth) methods.push({ start, end: end - 1 });
    declaration.lastIndex = end;
  }
  const cache = new Map();
  function proof(method) {
    if (cache.has(method)) return cache.get(method);
    const body = code.slice(method.start, method.end);
    const mask = masked.slice(method.start, method.end);
    const locals = [];
    const unknown = () => { cache.set(method, () => false); return cache.get(method); };
    // Nested classes introduce captures/fields; do not infer constants there.
    if (body.length > 50000 || /\b(?:class|interface|record|enum)\b|\bnew\b[^;]*\{/.test(mask)) {
      return unknown();
    }
    // Each brace block has its own bindings. The position map makes references
    // and RHS expressions resolve in the block where they actually occur.
    const scopes = [{ parent: -1, bindings: new Map() }];
    const scopeAt = new Uint16Array(mask.length + 1);
    let scope = 0;
    for (let i = 0; i < mask.length; i++) {
      scopeAt[i] = scope;
      if (mask[i] === '{') {
        if (scopes.length >= 1024) return unknown();
        scopes.push({ parent: scope, bindings: new Map() });
        scope = scopes.length - 1;
      } else if (mask[i] === '}') {
        if (!scope) return unknown();
        scope = scopes[scope].parent;
      }
    }
    if (scope) return unknown();
    scopeAt[mask.length] = 0;
    function resolve(name, position) {
      for (let id = scopeAt[position]; id >= 0; id = scopes[id].parent) {
        const entry = scopes[id].bindings.get(name);
        if (entry && entry.index <= position) return entry;
      }
      return null;
    }
    const owner = summaries.index.methods.find(m => m.start === method.start);
    for (const parameter of owner?.parameters || []) {
      if (!parameter) continue;
      const entry = { name: parameter.name, type: parameter.type, array: false, index: -1, end: 0, values: [], parameter: true };
      scopes[0].bindings.set(entry.name, entry);
      locals.push(entry);
    }
    const decl = /\b(String|int|boolean|char)\s*(\[\s*\])?\s+([A-Za-z_]\w*)\s*(\[\s*\])?\s*(?=[=;])/g;
    for (const m of mask.matchAll(decl)) {
      if (locals.length >= 64) return unknown();
      // Header declarations (for/resources), annotations and other unsupported
      // forms need more than brace scopes; leave the method unproved.
      const boundary = Math.max(mask.lastIndexOf(';', m.index - 1), mask.lastIndexOf('{', m.index - 1), mask.lastIndexOf('}', m.index - 1));
      if (!/^\s*(?:final\s+)?$/.test(mask.slice(boundary + 1, m.index))) {
        if (m[1] === 'String') return unknown();
        continue; // Unsupported primitive declarations are never facts.
      }
      const name = m[3];
      const bindings = scopes[scopeAt[m.index]].bindings;
      // Duplicate or overlapping declarations are not valid local bindings.
      if (bindings.has(name) || resolve(name, m.index)) return unknown();
      const entry = { name, type: m[1], array: !!(m[2] || m[4]), index: m.index, end: m.index + m[0].length, values: [] };
      bindings.set(name, entry);
      locals.push(entry);
    }
    // Balanced element boundaries prevent an inner index bracket or an
    // enclosing parenthesis from concealing an array write. Call arguments
    // remain escapes: this reader starts at the original reference suffix.
    function arrayReadOnly(start, before) {
      let i = start;
      while (i < mask.length && /\s/.test(mask[i])) i++;
      if (/^\.length\b/.test(mask.slice(i))) return true;
      if (mask[i] !== '[') return false;
      const stack = [];
      const limit = Math.min(mask.length, i + 4000);
      for (; i < limit; i++) {
        const c = mask[i];
        if (c === '[' || c === '(') {
          if (stack.length >= 64) return false;
          stack.push(c);
        } else if (c === ']' || c === ')') {
          if (stack.pop() !== (c === ']' ? '[' : '(')) return false;
          if (!stack.length) { i++; break; }
        } else if (c === '{' || c === '}' || c === ';') return false;
      }
      if (stack.length || i >= limit) return false;
      // Parenthesized element expressions are assignable Java variables.
      // Skip all closing wrappers conservatively, even call delimiters.
      while (i < mask.length && (/\s/.test(mask[i]) || mask[i] === ')')) i++;
      if (/^(?:=(?!=)|[+\-*/%&|^]=|(?:<<|>>|>>>)=|\+\+|--)/.test(mask.slice(i))) return false;
      while (before >= 0 && (/\s/.test(mask[before]) || mask[before] === '(')) before--;
      return !/\+\+|--/.test(mask.slice(Math.max(0, before - 1), before + 1));
    }
    const localNames = new Set(locals.map(entry => entry.name));
    for (const ref of mask.matchAll(/\b[A-Za-z_]\w*\b/g)) {
      const name = ref[0];
      if (!localNames.has(name)) continue;
      const entry = resolve(name, ref.index);
      if (!entry || entry.invalid) continue;
      let afterIndex = ref.index + name.length;
      let previous = ref.index - 1;
      while (previous >= 0 && /\s/.test(mask[previous])) previous--;
      while (afterIndex < mask.length && /\s/.test(mask[afterIndex])) afterIndex++;
      // Parentheses preserve Java variables (including increment operands).
      // Unwrap balanced immediate wrappers before looking for any write.
      while (mask[previous] === '(' && mask[afterIndex] === ')') {
        previous--; afterIndex++;
        while (previous >= 0 && /\s/.test(mask[previous])) previous--;
        while (afterIndex < mask.length && /\s/.test(mask[afterIndex])) afterIndex++;
      }
      const after = mask.slice(afterIndex);
      // A member with the same spelling belongs to its receiver, not a local.
      if (mask[previous] === '.') continue;
      if (/\+\+|--/.test(mask.slice(Math.max(0, previous - 1), previous + 1))) entry.invalid = true;
      // Ignore the declaration's brackets, which are not an element write.
      const tail = ref.index < entry.end ? mask.slice(entry.end) : after;
      const assignment = tail.match(/^\s*=(?!=)/);
      if (assignment) {
        const offset = (ref.index < entry.end ? entry.end : afterIndex) + assignment[0].length;
        const stop = mask.indexOf(';', offset);
        if (stop < 0) { entry.invalid = true; continue; }
        entry.values.push({ expression: body.slice(offset, stop), offset });
      } else if (/^\s*(?:[+\-*/%&|^]=|(?:<<|>>|>>>)=|\+\+|--)/.test(tail)) {
        entry.invalid = true;
      } else if (entry.array && ref.index >= entry.end) {
        // Arrays may be read as elements/length only: aliases and calls can mutate.
        if (!arrayReadOnly(ref.index + name.length, ref.index - 1)) {
          entry.invalid = true;
        }
      }
    }
    // Conditions must agree across every syntactic write, including writes in
    // currently unreachable arms. This avoids circular reachability proofs and
    // changed guards on a later loop iteration.
    function fact(expr, position, visiting = new Set(), budget = { left: 512 }) {
      return evaluate(expr, name => {
        const entry = resolve(name, position);
        if (!entry || entry.parameter || entry.index >= position || entry.invalid || entry.array || !entry.values.length || visiting.has(entry) || visiting.size > 32) return null;
        const next = new Set(visiting); next.add(entry);
        let result = null;
        for (const value of entry.values) {
          const current = fact(value.expression, value.offset, next, budget);
          if (!current || !(entry.type === current.type || entry.type === 'int' && current.type === 'char')) return null;
          const typed = { type: entry.type, value: current.value };
          if (result && (result.type !== typed.type || result.value !== typed.value)) return null;
          result = typed;
        }
        return result;
      }, budget);
    }
    const dead = excludedBranches(body, (expr, position) => fact(expr, position));
    const unreachable = position => dead.some(([start, end]) => position >= start && position < end);
    let remaining;
    function constant(expr, visiting = new Set(), position = Infinity, context = {}) {
      if (--remaining < 0 || expr.length > 4000) return false;
      if (context.budget && --context.budget.left < 0) return false;
      expr = expr.trim();
      if (!expr) return false;
      const value = fact(expr, position);
      if (value) return context.mode !== 'html' ||
        !String(value.type === 'char' ? String.fromCharCode(value.value) : value.value).includes('<');
      // Split concatenation only outside quoted strings, parentheses and indexes.
      let quote = null, depth = 0, last = 0;
      const parts = [];
      for (let i = 0; i < expr.length; i++) {
        const c = expr[i];
        if (quote) { if (c === '\\') i++; else if (c === quote) quote = null; continue; }
        if (c === '"' || c === "'") { quote = c; continue; }
        if (c === '(' || c === '[') depth++;
        if (c === ')' || c === ']') depth--;
        if (c === '+' && depth === 0) { parts.push(expr.slice(last, i)); last = i + 1; }
      }
      if (quote || depth !== 0) return false;
      if (parts.length) return [...parts, expr.slice(last)].every(p => constant(p, visiting, position, context));
      if (/^"(?:[^"\\]|\\.)*"$|^'(?:[^'\\]|\\.)*'$|^(?:true|false|null|\d+)$/.test(expr)) return context.mode !== 'html';
      if (expr.startsWith('(') && expr.endsWith(')')) return constant(expr.slice(1, -1), visiting, position, context);
      const split = expr.match(/^([\s\S]+)\.split\s*\(\s*("(?:[^"\\]|\\.)*")\s*\)$/);
      if (split) return constant(split[1], visiting, position, context);
      if (isSafeFact(summaries.callFact({ expression: expr, position: method.start + position, context,
        prove: (argument, mode) => constant(argument, visiting, position, { ...context, mode }) }), context.mode)) return true;
      const identifier = expr.match(/^([A-Za-z_]\w*)(?:\s*\[[^\]]+\])?$/);
      if (!identifier) return false;
      const entry = resolve(identifier[1], position);
      if (!entry || entry.index >= position || entry.invalid || visiting.has(entry) || visiting.size > 32) return false;
      if (entry.parameter && !isSafeFact(summaries.parameterFact({ methodStart: method.start, name: entry.name, context }), context.mode)) return false;
      if (!entry.values.length) return !!entry.parameter;
      if (expr.includes('[') !== entry.array) return false;
      const next = new Set(visiting); next.add(entry);
      const reachable = entry.values.filter(value => !unreachable(value.offset));
      return reachable.length > 0 && reachable.every(value => constant(value.expression, next, value.offset, context));
    }
    const bounded = (expr, visiting, position, context) => {
      remaining = 512;
      return constant(expr, visiting, position, { budget: { left: 10000, methods: new Set() }, stack: [], ...context });
    };
    bounded.unreachable = unreachable;
    bounded.literal = fact;
    bounded.type = (expr, position) => {
      const value = fact(expr, position);
      if (value) return value.type;
      const name = expr.trim();
      const entry = /^[A-Za-z_]\w*$/.test(name) ? resolve(name, position) : null;
      return entry && !entry.array && !entry.invalid ? entry.type : null;
    };
    cache.set(method, bounded);
    return bounded;
  }
  const offsets = [0];
  for (let i = 0; i < code.length; i++) if (code[i] === '\n') offsets.push(i + 1);
  const filter = (line, window, sink, allArgs) => {
    const lineStart = offsets[line];
    const re = new RegExp(sink.source, sink.flags.replace(/[gy]/g, '') + 'g');
    let found = false;
    for (const match of window.matchAll(re)) {
      const pos = lineStart + match.index;
      if (masked[pos] !== code[pos]) continue;
      const method = methods.find(m => pos >= m.start && pos < m.end);
      if (!method) return false;
      const args = callArgs(window, match.index + match[0].length);
      if (!args.length || !(allArgs ? args : args.slice(0, 1)).every(arg => proof(method)(arg, new Set(), pos - method.start))) return false;
      found = true;
    }
    return found;
  };
  // SQLI-002 can match an assembly without a call. Prove every matching
  // fragment in the scanner window, and every sink there, before suppressing.
  filter.sqlAssembly = (line, window, pattern, sink) => {
    const lineStart = offsets[line];
    let found = false;
    const calls = [];
    const callPattern = new RegExp(sink.source, sink.flags.replace(/[gy]/g, '') + 'g');
    for (const match of window.matchAll(callPattern)) {
      const pos = lineStart + match.index;
      if (masked[pos] !== code[pos]) continue;
      const method = methods.find(m => pos >= m.start && pos < m.end);
      const args = callArgs(window, match.index + match[0].length);
      if (!method || !args.length || !args.every(arg => proof(method)(arg, new Set(), pos - method.start))) return false;
      // Locate the actual call end using the already string-masked source.
      let end = pos + match[0].length, depth = 1;
      for (; end < method.end && depth; end++) {
        if (masked[end] === '(') depth++;
        if (masked[end] === ')') depth--;
      }
      if (depth) return false;
      calls.push([pos, end]);
    }
    const re = new RegExp(pattern.source, pattern.flags.replace(/[gy]/g, '') + 'g');
    for (const match of window.matchAll(re)) {
      const pos = lineStart + match.index;
      const method = methods.find(m => pos >= m.start && pos < m.end);
      if (!method) return false;
      if (calls.some(([start, end]) => pos >= start && pos < end)) { found = true; continue; }
      // The fragment must start the complete RHS of a simple assignment.
      const before = masked.slice(method.start, pos);
      const boundary = Math.max(before.lastIndexOf(';'), before.lastIndexOf('{'), before.lastIndexOf('}'));
      if (!/^\s*(?:(?:final\s+)?String\s+)?[A-Za-z_]\w*\s*=\s*$/.test(before.slice(boundary + 1))) return false;
      const stop = masked.indexOf(';', pos);
      if (stop < 0 || stop > method.end || !proof(method)(code.slice(pos, stop), new Set(), pos - method.start)) return false;
      found = true;
    }
    return found;
  };
  filter.valueAt = (expression, position, context = {}) => {
    const method = methods.find(m => position >= m.start && position < m.end);
    return !!method && proof(method)(expression, new Set(), position - method.start, context);
  };
  filter.literalAt = (expression, position) => {
    const method = methods.find(m => position >= m.start && position < m.end);
    return method ? proof(method).literal?.(expression, position - method.start) : null;
  };
  filter.typeAt = (expression, position) => {
    const method = methods.find(m => position >= m.start && position < m.end);
    return method ? proof(method).type?.(expression, position - method.start) : null;
  };
  filter.index = summaries.index;
  summaries.attach(filter);
  return filter;
}

module.exports = { constantSinkFilter };
