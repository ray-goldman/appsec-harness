'use strict';
const { maskStrings } = require('./languages');

function argumentsOf(text) {
  const masked = maskStrings(text, 'java'), args = [];
  let depth = 0, start = 0;
  for (let i = 0; i < masked.length; i++) {
    if ('([{'.includes(masked[i])) depth++;
    if (')]}'.includes(masked[i]) && --depth < 0) return null;
    if (masked[i] === ',' && !depth) { args.push(text.slice(start, i).trim()); start = i + 1; }
  }
  if (depth) return null;
  if (text.trim()) args.push(text.slice(start).trim());
  return args.every(Boolean) ? args : null;
}

function parseCall(expression) {
  if (expression.length > 4000) return null;
  const m = expression.trim().match(/^((?:[A-Za-z_]\w*\s*\.\s*)*)([A-Za-z_]\w*)\s*\(/);
  if (!m) return null;
  const text = expression.trim(), mask = maskStrings(text, 'java');
  let depth = 1, end = m[0].length;
  for (; end < mask.length && depth; end++) {
    if (mask[end] === '(') depth++;
    if (mask[end] === ')') depth--;
  }
  if (depth || end !== text.length) return null;
  const args = argumentsOf(text.slice(m[0].length, end - 1));
  return args ? { owner: m[1].replace(/\s/g, '').replace(/\.$/, ''), name: m[2], args } : null;
}

function indexJavaFile({ file, raw, code }) {
  const mask = maskStrings(code, 'java');
  const classes = [...mask.matchAll(/\b(class|interface|enum|record)\s+([A-Za-z_]\w*)/g)];
  const index = { file, raw, code, mask, methods: [], imports: new Map(), complete: false };
  index.package = mask.match(/\bpackage\s+([\w.]+)\s*;/)?.[1] || '';
  index.declaredClasses = classes.map(c => [index.package, c[2]].filter(Boolean).join('.'));
  if (code.length > 1000000 || /\\u+[0-9a-fA-F]{4}/.test(raw) || /"""|->|::/.test(code) ||
      classes.length !== 1 || classes[0][1] !== 'class') return index;
  index.className = classes[0][2];
  index.qualifiedName = [index.package, index.className].filter(Boolean).join('.');
  for (const m of mask.matchAll(/\bimport\s+(static\s+)?([\w.*]+)\s*;/g)) {
    if (m[1] || m[2].includes('*')) continue;
    const short = m[2].split('.').pop();
    index.imports.set(short, index.imports.has(short) ? null : m[2]);
  }
  const depths = new Uint16Array(mask.length + 1), pairs = new Map(), stack = [];
  for (let i = 0; i < mask.length; i++) {
    depths[i] = stack.length;
    if (mask[i] === '{') { if (stack.length >= 1024) return index; stack.push(i); }
    if (mask[i] === '}') {
      const start = stack.pop();
      if (start === undefined) return index;
      pairs.set(start, i);
    }
  }
  if (stack.length) return index;
  index.declarations = new Map();
  for (const m of mask.matchAll(/\b([A-Za-z_]\w*)\s*\([^{};]*\)\s*(?:throws\s+[\w.,\s]+)?\{/g)) {
    if (depths[m.index] === 1) index.declarations.set(m[1], (index.declarations.get(m[1]) || 0) + 1);
  }
  const decl = /\b(void|String|boolean|int|long|char|Object)\s+([A-Za-z_]\w*)\s*\(([^{};]*)\)\s*(?:throws\s+[\w.,\s]+)?\{/g;
  for (const m of mask.matchAll(decl)) {
    if (depths[m.index] !== 1) continue;
    const open = m.index + m[0].length - 1, end = pairs.get(open);
    if (end === undefined || index.methods.length >= 256) return index;
    const boundary = Math.max(mask.lastIndexOf(';', m.index - 1), mask.lastIndexOf('{', m.index - 1), mask.lastIndexOf('}', m.index - 1));
    const prefix = mask.slice(boundary + 1, m.index).trim();
    // Annotations and generics need a larger grammar. They are not helper targets.
    const modifiers = prefix.split(/\s+/);
    const supported = /^(?:(?:public|private|protected|static|final|synchronized|strictfp)\s*)*$/.test(prefix);
    const params = argumentsOf(m[3]);
    const parameters = params?.map(p => {
      const match = p.match(/^(?:final\s+)?([\w.]+)\s+([A-Za-z_]\w*)$/);
      return match ? { type: match[1], name: match[2] } : null;
    });
    const method = { id: `${file}:${open + 1}`, name: m[2], type: m[1], start: open + 1, end,
      nameOffset: m.index + m[0].indexOf(m[2]), parameters: parameters || [],
      private: modifiers.includes('private'), static: modifiers.includes('static'),
      supported: supported && !!parameters && parameters.length <= 16 && parameters.every(Boolean),
      returns: [] };
    const body = mask.slice(method.start, end);
    if (body.length > 50000 || /\bnew\b[^;]*\{/.test(body)) method.supported = false;
    for (const r of body.matchAll(/\breturn\b/g)) {
      const from = method.start + r.index + r[0].length, stop = mask.indexOf(';', from);
      if (stop < 0 || stop >= end || method.returns.length >= 32) { method.supported = false; break; }
      method.returns.push({ expression: code.slice(from, stop), offset: from });
    }
    index.methods.push(method);
  }
  index.at = position => index.methods.find(m => position >= m.start && position < m.end);
  index.complete = true;
  return index;
}

function shadowsType(index, name, project, depth = 0) {
  if (!/^[A-Za-z_]\w*$/.test(name)) return true;
  // Interface fields participate in unqualified value lookup too.
  if (/\bimplements\b/.test(index.mask)) return true;
  // Later declarators have no adjacent type token. Conservatively treat a
  // comma/name occurrence as possible value ownership, including array forms.
  if (new RegExp(`,\\s*${name}\\b`).test(index.mask)) return true;
  const re = new RegExp(`\\b([\\w.$<>\\[\\]]+)\\s+${name}\\b`, 'g');
  if ([...index.mask.matchAll(re)].some(m => !['class', 'interface', 'enum', 'record', 'package', 'import', 'return', 'throw', 'new'].includes(m[1]))) return true;
  const parent = index.mask.match(/\bextends\s+([\w.]+)/)?.[1];
  if (!parent) return false;
  if (!project?.complete || depth >= 4) return true;
  const source = project.resolve(index, parent);
  if (source) return shadowsType(source.index, name, project, depth + 1);
  let qualified = parent.includes('.') ? parent : index.imports.get(parent);
  if (!qualified && parent === 'HttpServlet' &&
      !project.classes.has([index.package, parent].filter(Boolean).join('.'))) {
    const http = [...index.mask.matchAll(/\bimport\s+((?:javax|jakarta)\.servlet\.http)\.\*\s*;/g)];
    if (http.length === 1) qualified = `${http[0][1]}.HttpServlet`;
  }
  // These library bases do not introduce the supported encoder/type owners.
  // Other missing bases may contain a same-named value and stay unknown.
  return !(['java.lang.Object', 'javax.servlet.http.HttpServlet', 'jakarta.servlet.http.HttpServlet'].includes(qualified) &&
    !project.classes.has(qualified));
}

module.exports = { indexJavaFile, parseCall, argumentsOf, shadowsType };
