'use strict';
const { parseCall, shadowsType, argumentsOf } = require('./java-methods');
const { formattingArray } = require('./java-format-arrays');

const HTML_ENCODERS = new Map([
  ['org.springframework.web.util.HtmlUtils', new Set(['htmlEscape'])],
  ['org.owasp.encoder.Encode', new Set(['forHtml', 'forHtmlContent'])],
  ['org.apache.commons.lang.StringEscapeUtils', new Set(['escapeHtml'])],
  ['org.apache.commons.lang3.StringEscapeUtils', new Set(['escapeHtml4'])],
  ['org.apache.commons.text.StringEscapeUtils', new Set(['escapeHtml4'])],
]);
function javaEncodingFact({ index, project, expression, argumentFacts }) {
  const call = parseCall(expression);
  if (!index.complete || !call || call.args.length !== 1 || !call.owner || !project?.complete ||
      shadowsType(index, call.owner.split('.')[0], project)) return null;
  const owner = call.owner.includes('.') ? call.owner : index.imports.get(call.owner);
  if (!HTML_ENCODERS.get(owner)?.has(call.name) || project.classes.has(owner)) return null;
  const facts = typeof argumentFacts === 'function' ? argumentFacts() : argumentFacts;
  const dependencies = facts.map((f, i) => !f.known || f.external || f.dependencies.length ? i : -1).filter(i => i >= 0);
  return { known: true, dependencies, external: dependencies.length > 0, encodings: ['html-text'], evidence: [] };
}

// Determine only whether the next dynamic value is in HTML document text.
// All attribute/raw-text/comment positions remain unsupported.
function htmlContext(text) {
  if (text === null || text.length > 16000) return 'unknown';
  // Browser comment and raw-text parsing includes abrupt closes, noscript and
  // script escaped states. Do not approximate those with a closing-tag regex.
  if (text.includes('<!--')) return 'unknown';
  let i = 0;
  while (i < text.length) {
    if (text[i] !== '<') { i++; continue; }
    const start = i, end = text.indexOf('>', i + 1);
    if (end < 0) return 'unknown';
    i = end + 1;
    // Only attribute-free tags have a supported lexical contract. A quote in
    // an unquoted attribute is not a quote delimiter in the browser tokenizer.
    const tag = text.slice(start, i).match(/^<(\/?)([A-Za-z][A-Za-z0-9-]*)\s*\/?>$/);
    if (!tag) return 'unknown';
    if (['script', 'style', 'textarea', 'title', 'xmp', 'iframe', 'noembed', 'noframes', 'plaintext', 'noscript'].includes(tag[2].toLowerCase())) return 'unknown';
  }
  return 'html-text';
}

function plusParts(expression) {
  let quote = null, depth = 0, last = 0;
  const parts = [];
  for (let i = 0; i < expression.length; i++) {
    const c = expression[i];
    if (quote) { if (c === '\\') i++; else if (c === quote) quote = null; continue; }
    if (c === '"' || c === "'") quote = c;
    else if ('([{'.includes(c)) depth++;
    else if (')]}'.includes(c)) depth--;
    else if (c === '+' && !depth) { parts.push(expression.slice(last, i)); last = i + 1; }
  }
  return !quote && !depth && parts.length ? [...parts, expression.slice(last)] : [expression];
}

function javaOutputFilter({ code, filter, project }) {
  const index = filter.index;
  const offsets = [0];
  for (let i = 0; i < code.length; i++) if (code[i] === '\n') offsets.push(i + 1);
  const sink = /\b(response)\s*\.\s*getWriter\s*\(\s*\)\s*\.\s*(print|println|write|append|printf)\s*\(/g;
  function callAt(match, limit) {
    if (/\.\s*$/.test(index.mask.slice(0, match.index))) return null;
    const start = match.index + match[0].length;
    let end = start, depth = 1;
    for (; end < limit && depth; end++) {
      if (index.mask[end] === '(') depth++;
      if (index.mask[end] === ')') depth--;
    }
    const args = !depth && argumentsOf(code.slice(start, end - 1));
    return args ? { args, end, position: match.index, kind: match[2] } : null;
  }
  function literal(expression, position) {
    const value = filter.literalAt(expression, position);
    if (!value) return null;
    return value.type === 'char' ? String.fromCharCode(value.value) : String(value.value);
  }
  function renderExpression(expression, position, output) {
    for (const part of plusParts(expression)) {
      const value = literal(part, position);
      if (value !== null) output.text = output.text === null ? null : output.text + value;
      else if (htmlContext(output.text) === 'html-text' && filter.valueAt(part, position, { mode: 'html' }) &&
               !filter.valueAt(part, position)) output.text += 'x';
      else return false;
      if (output.text?.length > 16000) return false;
    }
    return true;
  }
  function render(call, output) {
    let args = call.args;
    if (call.kind === 'printf' && /^java\.util\.Locale\.(?:ROOT|US|UK|ENGLISH)$/.test(args[0]?.trim())) args = args.slice(1);
    if (call.kind === 'write' && args.length === 1) {
      const scalar = filter.literalAt(args[0], call.position);
      if (scalar && ['int', 'char'].includes(scalar.type)) {
        output.text = output.text === null ? null : output.text + String.fromCharCode(scalar.value & 65535);
        return true;
      }
      // A direct copy cannot be changed between conversion and writing.
      // Stored arrays and writer slice overloads remain unsupported.
      const copy = args[0].match(/^([\s\S]+)\.toCharArray\s*\(\s*\)$/);
      if (copy) return renderExpression(copy[1], call.position, output);
    }
    if (call.kind !== 'printf') {
      if (args.length !== 1 || !renderExpression(args[0], call.position, output)) return false;
      if (call.kind === 'println' && output.text !== null) output.text += '\n';
      return true;
    }
    const format = literal(args[0] || '', call.position);
    if (format === null) return false;
    const array = args.length === 2 ? formattingArray(index, args[1], call, filter) : null;
    const substitutions = array || args.slice(1).map(expression => ({ expression, position: call.position }));
    let next = 1, last = 0;
    const re = /%((\d+)\$)?([s%n])/g;
    for (const m of format.matchAll(re)) {
      const prefix = format.slice(last, m.index);
      if (prefix.includes('%')) return false;
      output.text = output.text === null ? null : output.text + prefix;
      if (m[3] === '%' || m[3] === 'n') output.text = output.text === null ? null : output.text + (m[3] === '%' ? '%' : '\n');
      else {
        const n = m[2] ? Number(m[2]) : next++;
        const value = substitutions[n - 1];
        if (!value || !renderExpression(value.expression, value.position, output)) return false;
      }
      last = m.index + m[0].length;
    }
    if (format.slice(last).includes('%')) return false;
    output.text = output.text === null ? null : output.text + format.slice(last);
    return output.text === null || output.text.length <= 16000;
  }
  function contextBefore(method, position) {
    const before = code.slice(method.start, position);
    // A later iteration can enter with output produced after this sink.
    // Without a loop context fixed point, do not infer the initial stream.
    if (/\b(?:for|while|do)\b/.test(index.mask.slice(method.start, method.end))) return null;
    const response = method.parameters.find(p => p?.name === 'response');
    function servletType(type, short) {
      if (!type) return false;
      let qualified = type;
      if (!type.includes('.')) {
        if (index.imports.has(type)) qualified = index.imports.get(type);
        else {
          if (project?.classes.has([index.package, type].filter(Boolean).join('.'))) return false;
          const wildcards = [...index.mask.matchAll(/\bimport\s+([\w.]+)\.\*\s*;/g)];
          const http = wildcards.filter(m => /^(javax|jakarta)\.servlet\.http$/.test(m[1]));
          if (http.length !== 1 || wildcards.some(m => project?.classes.has(`${m[1]}.${type}`))) return false;
          qualified = `${http[0][1]}.${type}`;
        }
      }
      return ['javax', 'jakarta'].some(ns => qualified === `${ns}.servlet.http.${short}`) &&
        !project?.classes.has(qualified);
    }
    const fresh = /^\s*response\s*\.\s*resetBuffer\s*\(\s*\)\s*;\s*response\s*\.\s*setContentType\s*\(\s*"text\/html(?:;[^"\\]*)?"\s*\)\s*;/.test(before);
    const entry = ['doGet', 'doPost', 'service'].includes(method.name) &&
      servletType(index.mask.match(/\bextends\s+([\w.]+)/)?.[1], 'HttpServlet');
    if (!(entry || fresh) || !servletType(response?.type, 'HttpServletResponse') ||
        !project?.complete || ['javax', 'jakarta'].some(ns => ['HttpServlet', 'HttpServletResponse'].some(name => project.classes.has(`${ns}.servlet.http.${name}`)))) return null;
    const output = { text: '' }, covered = [];
    const re = new RegExp(sink.source, 'g');
    re.lastIndex = method.start;
    let count = 0;
    for (let m; (m = re.exec(code)) && m.index < position;) {
      if (++count > 64) return null;
      const call = callAt(m, position);
      if (!call || !render(call, output)) return null;
      covered.push([m.index - method.start, call.end - method.start]);
      re.lastIndex = call.end;
    }
    // Response setup is supported only when it cannot change the parser context.
    const setup = /\bresponse\s*\.\s*(setContentType|setHeader|setStatus|resetBuffer)\s*\(/g;
    for (const m of before.matchAll(setup)) {
      const absolute = { ...m, index: m.index + method.start, 2: m[1] };
      const call = callAt(absolute, position);
      if (!call) return null;
      if (m[1] === 'resetBuffer' && (!fresh || call.args.length || before.slice(0, m.index).trim())) return null;
      if (m[1] === 'setContentType' && !/^text\/html(?:;|$)/i.test(literal(call.args[0], call.position) || '')) return null;
      if (m[1] === 'setHeader') {
        const name = literal(call.args[0], call.position);
        if (name === null || name.toLowerCase() === 'content-type') return null;
      }
      covered.push([m.index, call.end - method.start]);
    }
    const rest = before.split('');
    for (const [a, b] of covered) for (let i = a; i < b; i++) rest[i] = ' ';
    if (/\bresponse\b/.test(rest.join(''))) return null;
    // Require each prior response operation to be a complete top-level
    // expression statement. Braces alone miss unbraced if/loop bodies.
    for (const [a] of covered) {
      const prefix = index.mask.slice(method.start, method.start + a);
      let depth = 0, parens = 0, boundary = 0;
      for (let i = 0; i < prefix.length; i++) {
        const c = prefix[i];
        if (c === '(' || c === '[') parens++;
        if (c === ')' || c === ']') parens--;
        if (c === '{') depth++;
        if (c === '}') { depth--; if (!depth && !parens) boundary = i + 1; }
        if (c === ';' && !depth && !parens) boundary = i + 1;
      }
      if (depth || parens || prefix.slice(boundary).trim()) return null;
    }
    return output;
  }
  return (line, window) => {
    if (!index?.complete || !filter.literalAt) return false;
    // The engine emits one finding per window. A second, unsupported receiver
    // must not borrow a proof for response.getWriter().
    if (/\bout\s*\.\s*(?:print|println|write|append|printf)\s*\(/.test(window)) return false;
    const allWriters = [...window.matchAll(/\.getWriter\s*\(\s*\)\s*\.\s*(?:print|println|write|append|printf)\s*\(/g)];
    if (allWriters.length !== [...window.matchAll(new RegExp(sink.source, 'g'))].length) return false;
    const re = new RegExp(sink.source, 'g');
    let found = false;
    for (const match of window.matchAll(re)) {
      const position = offsets[line] + match.index;
      const method = index.at(position);
      if (!method) return false;
      const call = callAt({ ...match, index: position }, method.end);
      if (!call) return false;
      let args = call.args;
      if (call.kind === 'printf' && /^java\.util\.Locale\.(?:ROOT|US|UK|ENGLISH)$/.test(args[0]?.trim())) args = args.slice(1);
      if (args.length && args.every(arg => filter.valueAt(arg, position))) { found = true; continue; }
      const output = contextBefore(method, position);
      if (!output || !render(call, output)) return false;
      found = true;
    }
    return found;
  };
}

module.exports = { javaEncodingFact, javaOutputFilter, htmlContext };
