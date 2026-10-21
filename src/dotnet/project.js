'use strict';
const { parseCSharp } = require('../parsers/csharp/parser');
const { tokenizeCSharp } = require('../parsers/csharp/lexer');

const SUMMARY_SCHEMA = 'kayfabe-dotnet-method-summary@1';
const SINKS = Object.freeze({
  sql: /\b(?:ExecuteSqlRaw|FromSqlRaw|ExecuteSqlCommand|SqlCommand|ExecuteNonQuery|ExecuteReader)\s*\(([^)]{0,2000})\)/g,
  command: /\b(?:Process\.Start|ProcessStartInfo|ShellExecute)\s*\(([^)]{0,2000})\)/g,
  xss: /\b(?:Html\.Raw|Response\.Write|WriteAsync)\s*\(([^)]{0,2000})\)/g,
  path: /\b(?:File\.(?:Read|Write|Delete)|PhysicalFile|FileStream)\s*\(([^)]{0,2000})\)/g,
  ssrf: /\b(?:HttpClient|WebRequest|GetAsync|PostAsync)\s*\(([^)]{0,2000})\)/g,
});
const SOURCES = Object.freeze({ request: /\bRequest\.(?:Query|Form|Headers|Cookies|QueryString)\b|\[From(?:Query|Body|Route|Form|Header)\]/,
  environment: /\b(?:Environment\.GetEnvironmentVariable|Environment\.GetCommandLineArgs)\s*\(/,
  file: /\b(?:File\.ReadAllText|File\.ReadAllBytes|File\.ReadLines)\s*\(/ });

function splitArgs(tokens, start, end) {
  const args = []; let depth = 0, begin = start;
  for (let i = start; i < end; i++) {
    if (['(', '[', '{', '<'].includes(tokens[i].text)) depth++;
    else if ([')', ']', '}', '>'].includes(tokens[i].text)) depth--;
    else if (tokens[i].text === ',' && depth === 0) { args.push(tokens.slice(begin, i)); begin = i + 1; }
  }
  if (begin < end) args.push(tokens.slice(begin, end));
  return args;
}
function isConstant(tokens) { return !tokens.some(t => t.kind === 'identifier' && !['true','false','null','nameof'].includes(t.text.replace(/^@/, ''))); }
function sanitizeCategory(body, category) {
  const neutralizers = { xss: /\b(?:HtmlEncode|Encode\.forHtml|HtmlEncoder\.Default\.Encode)\s*\(/,
    sql: /\b(?:SqlParameter|AddWithValue|FromSqlInterpolated|ExecuteSqlInterpolated)\b/,
    path: /\b(?:GetFullPath|IsPathRooted|StartsWith)\s*\(/,
    command: /\b(?:ArgumentList|EscapeArgument)\b/ };
  return !!neutralizers[category]?.test(body);
}
function buildDotnetProjectIndex(files, { maxMethods = 50000, maxCalls = 150000 } = {}) {
  const methods = [], parsed = [], unresolvedFiles = new Set(); let bytes = 0;
  for (const entry of files) {
    const file = entry.file || entry.rel;
    const source = entry.source || entry.raw || entry.code;
    if (!file || typeof source !== 'string' || !/\.cs$/i.test(file)) continue;
    bytes += Buffer.byteLength(source);
    if (bytes > 100 * 1024 * 1024 || methods.length > maxMethods) { unresolvedFiles.add(file); continue; }
    const ast = entry.ast || parseCSharp(source);
    if (!ast.complete) { unresolvedFiles.add(file); continue; }
    const lex = tokenizeCSharp(source);
    parsed.push({ file, source, ast, tokens: lex.tokens });
    for (const method of ast.methods) {
      const body = source.slice(method.bodyStart + 1, method.bodyEnd - 1);
      const parameters = method.parameters || [];
      const parameterToReturn = parameters.flatMap((parameter, index) => new RegExp(`\\breturn\\s+[^;]*\\b${parameter.name.replace(/[$]/g, '\\$&')}\\b`).test(body) ? [index] : []);
      const parameterToSink = [];
      for (const [category, pattern] of Object.entries(SINKS)) for (const match of body.matchAll(pattern)) for (let i = 0; i < parameters.length; i++) {
        if (new RegExp(`\\b${parameters[i].name.replace(/[$]/g, '\\$&')}\\b`).test(match[1])) parameterToSink.push({ parameter: i, category, sanitized: sanitizeCategory(match[1], category) });
      }
      const returnExpressions = [...body.matchAll(/\breturn\s+([^;]+);/g)].map(m => m[1]);
      const sourceToReturn = Object.entries(SOURCES).filter(([, re]) => returnExpressions.some(expression => re.test(expression))).map(([category]) => category);
      methods.push({ id: `${file}#${method.name}/${parameters.length}`, file, name: method.name, arity: parameters.length,
        visibility: method.visibility || 'unknown', start: method.start, end: method.end, body, parameters,
        summary: { schema: SUMMARY_SCHEMA, parameterToReturn, parameterToSink, parameterToFieldWrite: [], sourceToReturn, sourceToFieldWrite: [], sinkSanitizers: Object.fromEntries(parameterToSink.map(s => [s.category, s.sanitized])) } });
    }
  }
  const bySignature = new Map();
  for (const method of methods) { const key = `${method.name}/${method.arity}`; if (!bySignature.has(key)) bySignature.set(key, []); bySignature.get(key).push(method); }
  const calls = [];
  for (const unit of parsed) {
    const ts = unit.tokens;
    for (let i = 0; i + 1 < ts.length; i++) {
      if (ts[i].kind !== 'identifier' || ts[i + 1].text !== '(' || !/^[A-Za-z_]/.test(ts[i].text)) continue;
      if (methods.some(m => m.file === unit.file && m.start === ts[i].start)) continue;
      let depth = 0, end = -1;
      for (let j = i + 1; j < ts.length; j++) { if (ts[j].text === '(') depth++; else if (ts[j].text === ')' && --depth === 0) { end = j; break; } }
      if (end < 0) continue;
      const args = splitArgs(ts, i + 2, end), candidates = bySignature.get(`${ts[i].text.replace(/^@/, '')}/${args.length}`) || [];
      if (['if','for','foreach','while','switch','catch','using','nameof','typeof'].includes(ts[i].text)) continue;
      const unsupported = args.some(arg => arg.some(t => ['=', ':'].includes(t.text))) || candidates.some(m => unresolvedFiles.has(m.file));
      const resolved = candidates.length === 1 && !unsupported && !unresolvedFiles.has(unit.file);
      calls.push({ file: unit.file, name: ts[i].text.replace(/^@/, ''), arity: args.length, start: ts[i].start,
        caller: methods.find(m => m.file === unit.file && ts[i].start >= m.start && ts[i].start <= m.end)?.id || null,
        callee: resolved ? candidates[0].id : null, resolved, constantArguments: args.map(isConstant),
        reason: resolved ? null : candidates.length > 1 ? 'ambiguous-name-arity' : candidates.length === 0 ? 'no-visible-target' : unsupported ? 'unsupported-call-form-or-fallback' : 'unresolved' });
      if (calls.length > maxCalls) break;
    }
  }
  const internalsVisibleTo = parsed.some(unit => /\bInternalsVisibleTo(?:Attribute)?\b/.test(unit.source));
  for (const method of methods) {
    const callers = calls.filter(call => call.callee === method.id);
    const unresolvedByName = calls.some(call => call.name === method.name && !call.resolved);
    const suppressibleScope = method.visibility === 'private' || (method.visibility === 'internal' && !internalsVisibleTo);
    method.summary.constantOnlySuppressedParameters = suppressibleScope && callers.length > 0 && !unresolvedByName
      ? method.parameters.map((_, index) => index).filter(index => callers.every(call => call.constantArguments[index] === true))
      : [];
  }
  const unresolvedCalls = calls.filter(c => !c.resolved).length;
  return { summaryVersion: 1, summarySchema: SUMMARY_SCHEMA, methods, calls,
    diagnostics: { files: parsed.length + unresolvedFiles.size, parsedFiles: parsed.length, fallbackFiles: unresolvedFiles.size,
      methods: methods.length, calls: calls.length, unresolvedCalls, truncated: methods.length > maxMethods || calls.length > maxCalls, maxMethods, maxCalls } };
}

module.exports = { buildDotnetProjectIndex, SUMMARY_SCHEMA, SINKS, SOURCES };
