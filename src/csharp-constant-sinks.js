'use strict';

const { parseCSharp } = require('./parsers/csharp/parser');
const { tokenizeCSharp } = require('./parsers/csharp/lexer');
const { createCSharpValueProof } = require('./csharp-values');

const CONSTANT_TYPES = new Set(['string', 'String', 'char', 'int', 'long', 'short', 'byte', 'bool', 'float', 'double', 'decimal', 'var']);
const MAX_METHOD = 50000;

function splitAtTopLevel(tokens, delimiter) {
  const parts = []; let start = 0, depth = 0;
  for (let i = 0; i < tokens.length; i++) {
    const text = tokens[i].text;
    if (['(', '[', '{'].includes(text)) depth++;
    else if ([')', ']', '}'].includes(text)) depth--;
    else if (text === delimiter && depth === 0) { parts.push(tokens.slice(start, i)); start = i + 1; }
  }
  parts.push(tokens.slice(start));
  return parts;
}

function consumeExpression(tokens, start, end) {
  let depth = 0;
  for (let i = start; i < end; i++) {
    const text = tokens[i].text;
    if (['(', '[', '{'].includes(text)) depth++;
    else if ([')', ']', '}'].includes(text)) {
      if (depth === 0) return tokens.slice(start, i);
      depth--;
    } else if (text === ';' && depth === 0) return tokens.slice(start, i);
  }
  return tokens.slice(start, end);
}

function sinkExpression(tokens, ruleId, lineStart, lineEnd) {
  const line = tokens.filter(token => token.start >= lineStart && token.start < lineEnd);
  if (ruleId === 'CS-CMDI-001') {
    for (let i = 0; i + 3 < line.length; i++) {
      if (line[i].text === 'Process' && line[i + 1].text === '.' && line[i + 2].text === 'Start' && line[i + 3].text === '(') {
        let depth = 1, end = i + 4;
        for (; end < line.length && depth; end++) { if (line[end].text === '(') depth++; else if (line[end].text === ')') depth--; }
        if (depth) return null;
        const args = splitAtTopLevel(line.slice(i + 4, end - 1), ',');
        return args.length === 1 ? args[0] : null;
      }
    }
    for (let i = 0; i + 2 < line.length; i++) {
      if (line[i].text === '.' && line[i + 1].text === 'Arguments' && line[i + 2].text === '=') return consumeExpression(line, i + 3, line.length);
    }
    return null;
  }
  if (ruleId === 'CS-SQLI-001') {
    for (let i = 0; i + 2 < line.length; i++) {
      if (line[i].text === '.' && line[i + 1].text === 'CommandText' && line[i + 2].text === '=') return consumeExpression(line, i + 3, line.length);
    }
    for (let i = 0; i + 1 < line.length; i++) {
      const methodCall = ['FromSqlRaw', 'ExecuteSqlRaw', 'ExecuteSqlRawAsync', 'SqlQueryRaw'].includes(line[i].text);
      const constructor = line[i].text === 'SqlCommand' && line[i - 1]?.text === 'new';
      if (!methodCall && !constructor) continue;
      let open = i + 1;
      while (open < line.length && line[open].text !== '(') open++;
      if (open === line.length) return null;
      let depth = 1, end = open + 1;
      for (; end < line.length && depth; end++) { if (line[end].text === '(') depth++; else if (line[end].text === ')') depth--; }
      if (depth) return null;
      return splitAtTopLevel(line.slice(open + 1, end - 1), ',')[0];
    }
  }
  return null;
}

function parseLocalDeclarations(tokens) {
  const declarations = new Map();
  for (let i = 1; i < tokens.length; i++) {
    const name = tokens[i];
    if (name.kind !== 'identifier' || !['=', ';'].includes(tokens[i + 1]?.text)) continue;
    let previous = i - 1;
    while (previous >= 0 && ['?', ']', '['].includes(tokens[previous].text)) previous--;
    if (!CONSTANT_TYPES.has(tokens[previous]?.text)) continue;
    const key = name.text.replace(/^@/, '');
    if (!declarations.has(key)) declarations.set(key, []);
    declarations.get(key).push({ tokenIndex: i, nameIndex: i, type: tokens[previous].text });
  }
  return declarations;
}

function proveExpression(tokens, declarations, assignments, parameters, visiting = new Set(), depth = 0) {
  if (!tokens.length || tokens.length > 256 || depth > 24) return false;
  while (tokens[0]?.text === '(' && tokens.at(-1)?.text === ')') {
    let level = 0, wraps = true;
    for (let i = 0; i < tokens.length; i++) {
      if (tokens[i].text === '(') level++;
      else if (tokens[i].text === ')' && --level === 0 && i !== tokens.length - 1) { wraps = false; break; }
    }
    if (!wraps) break;
    tokens = tokens.slice(1, -1);
  }
  const plus = splitAtTopLevel(tokens, '+');
  if (plus.length > 1) return plus.every(part => proveExpression(part, declarations, assignments, parameters, visiting, depth + 1));
  if (tokens.length === 1) {
    const token = tokens[0];
    if (['string', 'char', 'number'].includes(token.kind) || ['true', 'false', 'null'].includes(token.text)) return true;
    if (token.kind !== 'identifier') return false;
    const name = token.text.replace(/^@/, '');
    if (parameters.has(name) || visiting.has(name) || declarations.get(name)?.length !== 1) return false;
    const writes = assignments.get(name) || [];
    if (!writes.length) return false;
    const next = new Set(visiting); next.add(name);
    return writes.every(rhs => proveExpression(rhs, declarations, assignments, parameters, next, depth + 1));
  }
  return false;
}

function directConstantSink({ code, line, ruleId, parsed: suppliedParse }) {
  if (typeof code !== 'string' || !Number.isInteger(line) || line < 0 || code.length > 2 * 1024 * 1024 ||
      !['CS-CMDI-001', 'CS-SQLI-001'].includes(ruleId)) return false;
  if (/\busing\s+(?:String|var)\s*=/.test(code)) return false;
  const lines = code.split(/\r?\n/);
  if (line >= lines.length) return false;
  const lineStart = lines.slice(0, line).reduce((sum, value) => sum + value.length + 1, 0);
  const lineEnd = lineStart + lines[line].length;
  const parsed = suppliedParse || parseCSharp(code);
  if (!parsed.complete) return false;
  const methods = parsed.methods.filter(method => method.start <= lineStart && method.end >= lineEnd);
  if (methods.length !== 1) return false;
  const method = methods[0];
  if (method.end - method.start > MAX_METHOD) return false;
  const lexed = tokenizeCSharp(code.slice(method.start, method.end));
  if (lexed.errors.length || lexed.tokens.some(token => token.kind === 'interpolated-string')) return false;
  const tokens = lexed.tokens;
  const methodParams = new Set((method.parameters || []).map(parameter => parameter.name));
  const declarations = parseLocalDeclarations(tokens);
  const assignments = new Map();
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i], name = token.text.replace(/^@/, '');
    if (token.kind !== 'identifier' || tokens[i - 1]?.text === '.') continue;
    if (tokens[i + 1]?.text !== '=' || tokens[i + 2]?.text === '=') continue;
    if (!declarations.has(name)) continue;
    let end = i + 2, nesting = 0;
    for (; end < tokens.length; end++) {
      if (['(', '[', '{'].includes(tokens[end].text)) nesting++;
      else if ([')', ']', '}'].includes(tokens[end].text)) { if (nesting === 0) break; nesting--; }
      else if (tokens[end].text === ';' && nesting === 0) break;
    }
    if (end >= tokens.length || tokens[end].text !== ';') return false;
    if (!assignments.has(name)) assignments.set(name, []);
    assignments.get(name).push(tokens.slice(i + 2, end));
  }
  const expression = sinkExpression(tokens, ruleId, lineStart - method.start, lineEnd - method.start);
  if (!expression) return false;
  const relevant = new Set();
  const pending = expression.filter(token => token.kind === 'identifier').map(token => token.text.replace(/^@/, ''));
  while (pending.length) {
    const name = pending.pop();
    if (relevant.has(name)) continue;
    relevant.add(name);
    for (const rhs of assignments.get(name) || []) for (const token of rhs) {
      if (token.kind === 'identifier') pending.push(token.text.replace(/^@/, ''));
    }
  }
  for (let i = 0; i < tokens.length; i++) {
    const name = tokens[i].kind === 'identifier' ? tokens[i].text.replace(/^@/, '') : null;
    if (!name || !relevant.has(name)) continue;
    if (['++', '--', '+=', '-=', '*=', '/=', '%='].includes(tokens[i + 1]?.text) || ['++', '--'].includes(tokens[i - 1]?.text) ||
        ['ref', 'out'].includes(tokens[i - 1]?.text)) return false;
    if (tokens[i + 1]?.text === '=>' && tokens.slice(i + 2).some(token => token.kind === 'identifier' && relevant.has(token.text.replace(/^@/, '')))) return false;
  }
  const opens=[];
  for(let i=0;i<tokens.length;i++) {
    if(tokens[i].text==='(')opens.push(i);
    else if(tokens[i].text===')') {
      const open=opens.pop();
      if(open!==undefined&&tokens[i+1]?.text==='='&&tokens.slice(open+1,i).some(token=>token.kind==='identifier'&&relevant.has(token.text.replace(/^@/,''))))return false;
    }
  }
  return !!expression && proveExpression(expression, declarations, assignments, methodParams);
}

function createCSharpConstantSinkProof(code) {
  let parsed, tokens, proveValue;
  return (line, ruleId) => {
    if (typeof code !== 'string' || code.length > 2 * 1024 * 1024 || !Number.isInteger(line) || line < 0 ||
        !['CS-CMDI-001', 'CS-SQLI-001'].includes(ruleId)) return false;
    parsed ||= parseCSharp(code);
    if (directConstantSink({ code, line, ruleId, parsed })) return true;
    if (!parsed.complete) return false;
    const lines = code.split(/\r?\n/);
    if (line >= lines.length) return false;
    const start = lines.slice(0, line).reduce((sum, text) => sum + text.length + 1, 0);
    tokens ||= tokenizeCSharp(code).tokens;
    const expression = sinkExpression(tokens, ruleId, start, start + lines[line].length);
    if (!expression?.length) return false;
    proveValue ||= createCSharpValueProof(code, parsed);
    return proveValue(expression);
  };
}

function isConstantCSharpSink({ code, line, ruleId }) {
  return createCSharpConstantSinkProof(code)(line, ruleId);
}

module.exports = { isConstantCSharpSink, createCSharpConstantSinkProof };
