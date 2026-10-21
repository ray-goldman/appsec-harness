'use strict';

const { parseCSharp } = require('../parsers/csharp/parser');
const { tokenizeCSharp } = require('../parsers/csharp/lexer');

function findOwners(source, ast, tokens) {
  const pairs = new Map(), stack = [];
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i].text === '{') stack.push(i);
    else if (tokens[i].text === '}') { const open = stack.pop(); if (open !== undefined) pairs.set(open, i); }
  }
  const types = [];
  for (let i = 0; i < tokens.length - 2; i++) {
    if (!['class','struct','interface','record'].includes(tokens[i].text) || tokens[i + 1].kind !== 'identifier') continue;
    let open = i + 2; while (open < tokens.length && !['{',';'].includes(tokens[open].text)) open++;
    if (tokens[open]?.text === '{' && pairs.has(open)) types.push({ name: tokens[i + 1].text.replace(/^@/, ''), start: tokens[i].start, bodyStart: tokens[open].start, bodyEnd: tokens[pairs.get(open)].end });
  }
  const fileScoped = source.match(/\bnamespace\s+([\w.]+)\s*;/)?.[1] || '';
  const namespaces = [];
  for (let i = 0; i < tokens.length - 1; i++) if (tokens[i].text === 'namespace') {
    let name = '', j = i + 1;
    while (j < tokens.length && tokens[j].text !== '{' && tokens[j].text !== ';') { if (tokens[j].kind === 'identifier') name += (name ? '.' : '') + tokens[j].text.replace(/^@/, ''); j++; }
    if (tokens[j]?.text === '{' && pairs.has(j)) namespaces.push({ name, start: tokens[j].start, end: tokens[pairs.get(j)].end });
  }
  return ast.methods.map(method => {
    const owner = types.filter(t => method.start >= t.bodyStart && method.end <= t.bodyEnd).sort((a,b) => (a.bodyEnd-a.bodyStart)-(b.bodyEnd-b.bodyStart))[0];
    const ns = namespaces.filter(n => method.start >= n.start && method.end <= n.end).sort((a,b) => (a.end-a.start)-(b.end-b.start))[0]?.name || fileScoped;
    return { ...method, namespace: ns, typeName: owner?.name || null, ownerResolved: !!owner };
  });
}

function buildDotnetProjectIndex(files) {
  const methods = [], types = new Map();
  for (const entry of files) {
    const file = entry.file || entry.rel, source = entry.source || entry.raw || entry.code;
    if (!file || typeof source !== 'string' || !/\.cs$/i.test(file)) continue;
    const ast = entry.ast || parseCSharp(source); if (!ast.complete) continue;
    const tokens = tokenizeCSharp(source).tokens;
    for (const m of findOwners(source, ast, tokens)) {
      if (!m.ownerResolved) continue;
      const typeId = [m.namespace, m.typeName].filter(Boolean).join('.');
      if (!types.has(typeId)) types.set(typeId, { id: typeId, namespace: m.namespace, name: m.typeName, files: new Set(), partial: false });
      const type = types.get(typeId); type.files.add(file);
      const signature = (m.parameters || []).map(p => (p.type || '?').replace(/\s+/g, '')).join(',');
      methods.push({ id: `${typeId}.${m.name}/${m.parameters.length}(${signature})`, file, namespace: m.namespace, typeId, name: m.name, arity: m.parameters.length, parameterTypes: (m.parameters || []).map(p => p.type), parameters: m.parameters, visibility: m.visibility, start: m.start, end: m.end });
    }
  }
  for (const type of types.values()) { type.files = [...type.files].sort(); type.partial = type.files.length > 1; }
  return { schemaVersion: 1, types: [...types.values()].sort((a,b) => a.id.localeCompare(b.id)), methods: methods.sort((a,b) => a.id.localeCompare(b.id) || a.file.localeCompare(b.file)) };
}

module.exports = { buildDotnetProjectIndex };
