'use strict';
const { maskStrings } = require('./languages');

// This is a bounded proof for local String values, not a Java parser. Unknown
// syntax retains the warning. Inspect all writes, including writes after a sink
// which could affect a later loop iteration.
function constantSinkFilter(code, callArgs) {
  const masked = maskStrings(code, 'java');
  if (/\\u[0-9a-fA-F]{4}|"""|->/.test(code)) return () => false;
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
    const locals = new Map();
    // Nested classes introduce captures/fields; do not infer constants there.
    if (body.length > 50000 || /\b(?:class|interface|record)\b|new\s+\w+\s*\([^;]*\)\s*\{/.test(mask)) {
      cache.set(method, () => false); return cache.get(method);
    }
    const decl = /\bString\s*(\[\s*\])?\s+([A-Za-z_]\w*)\s*(\[\s*\])?\s*(?=[=;])/g;
    let blockDepth = 0, previous = 0;
    for (const m of mask.matchAll(decl)) {
      if (locals.size >= 64) {
        cache.set(method, () => false); return cache.get(method);
      }
      const name = m[2];
      if (locals.has(name)) locals.set(name, null);
      else {
        for (const char of mask.slice(previous, m.index)) {
          if (char === '{') blockDepth++;
          if (char === '}') blockDepth--;
        }
        previous = m.index;
        locals.set(name, blockDepth ? null : { array: !!(m[1] || m[3]), index: m.index, end: m.index + m[0].length, values: [] });
      }
    }
    for (const [name, entry] of locals) {
      if (!entry) continue;
      const references = new RegExp('\\b' + name + '\\b', 'g');
      for (const ref of mask.matchAll(references)) {
        const after = mask.slice(ref.index + name.length);
        const before = mask.slice(0, ref.index);
        if (/\.\s*$/.test(before)) { entry.invalid = true; break; }
        // Ignore the declaration's brackets, which are not an element write.
        const tail = ref.index < entry.end ? mask.slice(entry.end) : after;
        const assignment = tail.match(/^\s*=(?!=)/);
        if (assignment) {
          const offset = (ref.index < entry.end ? entry.end : ref.index + name.length) + assignment[0].length;
          const stop = mask.indexOf(';', offset);
          if (stop < 0) { entry.invalid = true; break; }
          entry.values.push({ expression: body.slice(offset, stop), offset });
        } else if (/^\s*(?:[+\-*/%&|^]=|\+\+|--)/.test(tail)) {
          entry.invalid = true; break;
        } else if (entry.array && ref.index >= entry.end) {
          // Arrays may be read as elements/length only: aliases and calls can mutate.
          if (!/^\s*(?:\[[^\]]*\](?!\s*(?:[+\-*/%&|^]?=|\+\+|--))|\.length\b)/.test(after)) {
            entry.invalid = true; break;
          }
        }
      }
    }
    let remaining;
    function constant(expr, visiting = new Set(), position = Infinity) {
      if (--remaining < 0 || expr.length > 4000) return false;
      expr = expr.trim();
      if (!expr) return false;
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
      if (parts.length) return [...parts, expr.slice(last)].every(p => constant(p, visiting, position));
      if (/^"(?:[^"\\]|\\.)*"$|^'(?:[^'\\]|\\.)*'$|^(?:true|false|null|\d+)$/.test(expr)) return true;
      if (expr.startsWith('(') && expr.endsWith(')')) return constant(expr.slice(1, -1), visiting, position);
      const split = expr.match(/^([\s\S]+)\.split\s*\(\s*("(?:[^"\\]|\\.)*")\s*\)$/);
      if (split) return constant(split[1], visiting, position);
      const identifier = expr.match(/^([A-Za-z_]\w*)(?:\s*\[[^\]]+\])?$/);
      if (!identifier) return false;
      const name = identifier[1], entry = locals.get(name);
      if (!entry || entry.index >= position || entry.invalid || !entry.values.length || visiting.has(name) || visiting.size > 32) return false;
      if (expr.includes('[') !== entry.array) return false;
      const next = new Set(visiting); next.add(name);
      return entry.values.every(value => constant(value.expression, next, Math.min(position, value.offset)));
    }
    const bounded = (expr, visiting, position) => {
      remaining = 512;
      return constant(expr, visiting, position);
    };
    cache.set(method, bounded);
    return bounded;
  }
  const offsets = [0];
  for (let i = 0; i < code.length; i++) if (code[i] === '\n') offsets.push(i + 1);
  return (line, window, sink, allArgs) => {
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
}

module.exports = { constantSinkFilter };
