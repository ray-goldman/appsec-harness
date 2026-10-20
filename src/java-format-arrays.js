'use strict';
const { argumentsOf } = require('./java-methods');

// An intentionally narrow ownership proof: a top-level local initializer and
// exactly one use, as the entire varargs carrier of this printf call.
// Any other reference (including a later write or escape) leaves it unknown.
function formattingArray(index, expression, call) {
  const name = expression.trim();
  if (!index?.complete || !/^[A-Za-z_]\w*$/.test(name)) return null;
  const method = index.at(call.position);
  if (!method || method.end - method.start > 50000) return null;
  const body = index.mask.slice(method.start, method.end);
  if (/\b(?:class|interface|enum|record|for|while|do)\b/.test(body)) return null;
  const refs = [...body.matchAll(new RegExp(`\\b${name}\\b`, 'g'))];
  if (refs.length !== 2) return null;
  const decl = new RegExp(`\\b(?:Object|String)\\s*\\[\\s*\\]\\s+${name}\\s*=\\s*\\{`, 'g');
  const matches = [...body.matchAll(decl)];
  if (matches.length !== 1) return null;
  const m = matches[0], open = m.index + m[0].length - 1;
  // Declaration must be a whole statement in the method's outer block.
  let braces = 0, parens = 0, boundary = 0;
  for (let i = 0; i < m.index; i++) {
    const c = body[i];
    if (c === '(' || c === '[') parens++;
    if (c === ')' || c === ']') parens--;
    if (c === '{') braces++;
    if (c === '}') { braces--; if (!braces && !parens) boundary = i + 1; }
    if (c === ';' && !braces && !parens) boundary = i + 1;
  }
  if (braces || parens || !/^\s*(?:final\s+)?$/.test(body.slice(boundary, m.index))) return null;
  const close = body.indexOf('}', open + 1);
  if (close < 0 || close - open > 4000 || /[{};]/.test(body.slice(open + 1, close)) ||
      !/^\s*;/.test(body.slice(close + 1))) return null;
  const position = method.start + open + 1;
  const values = argumentsOf(index.code.slice(position, method.start + close));
  if (!values?.length || values.length > 32 || method.start + close >= call.position) return null;
  const use = method.start + refs[1].index;
  if (refs[0].index < m.index || refs[0].index >= open ||
      use < call.position || use >= call.end) return null;
  // The caller has already required exactly (format, array) after Locale.
  // Binding each element at its initializer avoids borrowing a later scope.
  return values.map(expression => ({ expression, position }));
}

module.exports = { formattingArray };
