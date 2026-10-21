'use strict';

function tokenizeCSharp(source) {
  if (typeof source !== 'string') throw new TypeError('C# source must be a string');
  const tokens = [], regions = [], errors = [], directives = [];
  let i = 0;
  const push = (kind, start, end) => tokens.push({ kind, text: source.slice(start, end), start, end });
  const error = (message, start) => errors.push({ message, start });
  const isIdStart = c => /[A-Za-z_]/.test(c || '');
  const isId = c => /[A-Za-z0-9_]/.test(c || '');
  function scanQuoted(start, quoteAt, quote, verbatim, rawQuotes = 0) {
    let p = quoteAt + (rawQuotes || 1);
    if (rawQuotes) {
      const close = '"'.repeat(rawQuotes);
      const end = source.indexOf(close, p);
      if (end < 0) { error('unterminated raw string', start); return source.length; }
      p = end + rawQuotes;
      if (source[p] === 'u' && source[p + 1] === '8') p += 2;
      return p;
    }
    while (p < source.length) {
      if (!verbatim && source[p] === '\\') { p += 2; continue; }
      if (verbatim && source[p] === '"' && source[p + 1] === '"') { p += 2; continue; }
      if (source[p] === quote) {
        p++;
        if (quote === '"' && source[p] === 'u' && source[p + 1] === '8') p += 2;
        return p;
      }
      if (quote === '"' && !verbatim && source[p] === '\n') break;
      if (quote === "'" && source[p] === '\n') break;
      p++;
    }
    error(quote === "'" ? 'unterminated character literal' : 'unterminated string literal', start);
    return source.length;
  }
  while (i < source.length) {
    const start = i, c = source[i];
    if (c === '\n' || c === '\r' || /\s/.test(c)) { i++; continue; }
    if (c === '/' && source[i + 1] === '/') { i += 2; while (i < source.length && source[i] !== '\n') i++; continue; }
    if (c === '/' && source[i + 1] === '*') {
      i += 2; const end = source.indexOf('*/', i);
      if (end < 0) { error('unterminated block comment', start); i = source.length; } else i = end + 2;
      continue;
    }
    if (c === '#' && !source.slice(source.lastIndexOf('\n', i - 1) + 1, i).trim()) {
      const lineEnd = source.indexOf('\n', i), end = lineEnd < 0 ? source.length : lineEnd;
      const text = source.slice(i, end), match = text.match(/^#\s*([A-Za-z]+)\b/);
      const directive = match?.[1]?.toLowerCase();
      if (!directive || !['if','elif','else','endif','region','endregion','define','undef','nullable','pragma','warning','error','line'].includes(directive)) error('unsupported preprocessor directive', i);
      else {
        if (directive === 'if') directives.push({ directive, start: i });
        else if (directive === 'endif') {
          if (!directives.length) error('unmatched #endif', i);
          else { const open = directives.pop(); regions.push({ kind: 'preprocessor', directive: 'if', start: open.start, end }); }
        } else if (!directives.length) error(`unmatched #${directive}`, i);
      }
      regions.push({ kind: 'directive', directive: match?.[1] || 'unknown', start: i, end });
      i = end; continue;
    }
    // C# regular, verbatim, interpolated, and raw strings. Interpolation text is opaque at this layer.
    let prefix = 0, verbatim = false, interpolated = false;
    if (c === '$') {
      interpolated = true; prefix = 1;
      if (source[i + 1] === '@') { verbatim = true; prefix++; }
    } else if (c === '@' && source[i + 1] === '$') { verbatim = true; interpolated = true; prefix = 2; }
    else if (c === '@' && source[i + 1] === '"') { verbatim = true; prefix = 1; }
    const quoteAt = i + prefix;
    if ((prefix || c === '"') && source[quoteAt] === '"') {
      let qcount = 0; while (source[quoteAt + qcount] === '"') qcount++;
      const raw = qcount >= 3 ? qcount : 0;
      i = scanQuoted(start, quoteAt, '"', verbatim, raw);
      push(interpolated ? 'interpolated-string' : 'string', start, i); continue;
    }
    if (c === "'") { i = scanQuoted(start, i, "'", false); push('char', start, i); continue; }
    if (isIdStart(c) || c === '@' && isIdStart(source[i + 1])) {
      i += c === '@' ? 2 : 1; while (isId(source[i])) i++; push('identifier', start, i); continue;
    }
    if (/\d/.test(c)) { i++; while (/[\w.]/.test(source[i] || '')) i++; push('number', start, i); continue; }
    const op = ['=>','==','!=','<=','>=','??','?.','::','&&','||','++','--','+=','-=','*=','/=','??=','?.','<<','>>'].find(x => source.startsWith(x, i));
    i += op ? op.length : 1; push('punctuation', start, i);
  }
  for (const open of directives) error('unterminated preprocessor conditional', open.start);
  return { tokens, regions, errors };
}

module.exports = { tokenizeCSharp };
