'use strict';
const { maskStrings, analyzeTaint } = require('./languages');

// Bounded function ownership for immutable local strings. Unknown bindings keep
// file-wide evidence; generic sanitizer names never establish local safety.
function goFunctionTaint(code, raw, fallback) {
  const none = () => fallback;
  if (code.length > 100000 || /[^\x00-\x7f]|\x00|go:linkname|"unsafe"|"C"/.test(raw) ||
      (raw.includes('`') && raw.includes('\\'))) return none;
  const mask = maskStrings(code, 'go'), blocks = new Map(), stack = [], depths = new Uint16Array(mask.length);
  for (let i = 0; i < mask.length; i++) {
    depths[i] = stack.length;
    if (mask[i] === '{') { if (stack.length >= 64) return none; stack.push(i); }
    if (mask[i] === '}') {
      const start = stack.pop();
      if (start === undefined) return none;
      blocks.set(start, i);
    }
  }
  if (stack.length) return none;
  const starts = [0];
  for (let i = 0; i < code.length; i++) if (code[i] === '\n') starts.push(i + 1);
  const at = new Map();
  let count = 0;
  for (const fn of mask.matchAll(/^func\s+[A-Za-z_]\w*\([^{}\n]*\)[^{}\n]*\{/gm)) {
    if (++count > 256) return none;
    const open = fn.index + fn[0].length - 1, end = blocks.get(open);
    if (depths[open] !== 0 || end === undefined || end - open > 16000) continue;
    const body = code.slice(open + 1, end), bodyMask = mask.slice(open + 1, end);
    if (/\b(?:func|goto|go|defer)\b/.test(bodyMask) || fn[0].match(/\bfunc\b/g).length !== 1) continue;
    const locals = new Map();
    const ambiguousBindings = /\b(?:if|for|switch|select|range)\b|&/.test(bodyMask);
    const literal = /^[ \t]*(?:(?:var|const)\s+([A-Za-z_]\w*)(?:\s+string)?\s*=|([A-Za-z_]\w*)\s*:=)\s*"(?:[^"\\\n]|\\.)*"[ \t]*;?[ \t]*$/gm;
    for (const decl of body.matchAll(literal)) {
      if (ambiguousBindings) break;
      const name = decl[1] || decl[2], absolute = open + 1 + decl.index;
      if (name === '_' || depths[absolute] !== 1 || locals.size >= 64) continue;
      if (new RegExp(`\\b${name}\\b`).test(fn[0])) continue;
      const nameOffset = decl.index + decl[0].indexOf(name);
      if (bodyMask.slice(nameOffset, nameOffset + name.length) !== name) continue;
      let valid = true, uses = 0;
      for (const use of bodyMask.matchAll(new RegExp(`\\b${name}\\b`, 'g'))) {
        if (++uses > 256) { valid = false; break; }
        if (use.index === nameOffset) continue;
        let cursor = use.index + name.length, skipped = 0;
        while (cursor < bodyMask.length && /[\s)]/.test(bodyMask[cursor]) && skipped <= 256) { cursor++; skipped++; }
        const after = bodyMask.slice(cursor);
        // Reject writes, pointer escape, declarations, and ambiguous tuple uses.
        if (skipped > 256 || /^(?:[:+*/%&|^=-]=?|--|\+\+|,|[A-Za-z_])/.test(after)) {
          valid = false; break;
        }
      }
      if (valid) locals.set(name, absolute + decl[0].length);
    }
    const firstLine = starts.findIndex(offset => offset > open);
    if (firstLine < 0) continue;
    const local = analyzeTaint(body.split('\n'), 'go');
    const strict = analyzeTaint(body.split('\n'), 'go', { genericSanitizers: false });
    for (let line = firstLine; line < starts.length && starts[line] < end; line++) {
      const lineEnd = line + 1 < starts.length ? starts[line + 1] - 1 : code.length;
      if (lineEnd > end) continue;
      const safe = [...locals].filter(([, declared]) => declared < starts[line]).map(([name]) => name);
      const lineTainted = (text, pathRule) => {
        const direct = (pathRule ? strict : local).lineTainted(text);
        if (direct) return direct.from === undefined ? direct : { ...direct, from: direct.from + firstLine - 1 };
        let query = text;
        const masked = maskStrings(text, 'go');
        for (const name of safe) {
          const re = new RegExp(`\\b${name}\\b`, 'g');
          query = query.replace(re, (word, offset) =>
            masked.slice(offset, offset + word.length) === word && !/\.\s*$/.test(masked.slice(0, offset))
              ? ' '.repeat(word.length) : word);
        }
        return fallback.lineTainted(query);
      };
      at.set(line, {
        normal: { ...fallback, lineTainted: text => lineTainted(text, false) },
        path: { ...fallback, lineTainted: text => lineTainted(text, true) },
      });
    }
  }
  return (line, rule) => at.get(line)?.[rule === 'GO-PATH-001' ? 'path' : 'normal'] || fallback;
}
module.exports = { goFunctionTaint };
