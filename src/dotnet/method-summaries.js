'use strict';
const { createMethodSummary } = require('./summary-schema');

const SINKS = Object.freeze({
  sql: /\b(?:ExecuteSqlRaw|FromSqlRaw|ExecuteSqlCommand|SqlCommand|ExecuteNonQuery|ExecuteReader)\s*\(([^)]{0,2000})\)/g,
  command: /\b(?:Process\.Start|ShellExecute)\s*\(([^)]{0,2000})\)/g,
  xss: /\b(?:Html\.Raw|Response\.Write|WriteAsync)\s*\(([^)]{0,2000})\)/g,
  path: /\b(?:File\.(?:Read|Write|Delete)|PhysicalFile|FileStream)\s*\(([^)]{0,2000})\)/g,
  ssrf: /\b(?:HttpClient|WebRequest|GetAsync|PostAsync)\s*\(([^)]{0,2000})\)/g,
});
const SANITIZERS = Object.freeze({ xss: /\b(?:HtmlEncode|HtmlEncoder\.Default\.Encode|Encode\.forHtml)\s*\(/,
  sql: /\b(?:SqlParameter|AddWithValue|FromSqlInterpolated|ExecuteSqlInterpolated)\b/,
  path: /\b(?:GetFullPath|IsPathRooted|StartsWith)\s*\(/,
  command: /\b(?:ArgumentList|EscapeArgument)\b/ });
const SOURCES = Object.freeze({ request: /\bRequest\.(?:Query|Form|Headers|Cookies|QueryString)\b|\[From(?:Query|Body|Route|Form|Header)\]/,
  environment: /\bEnvironment\.(?:GetEnvironmentVariable|GetCommandLineArgs)\s*\(/,
  file: /\bFile\.(?:ReadAllText|ReadAllBytes|ReadLines)\s*\(/ });

function summarizeMethod(method) {
  const body = method.body || '', parameters = method.parameters || [];
  const parameterToReturn = parameters.flatMap((p,i) => new RegExp(`\\breturn\\s+[^;]*\\b${p.name.replace(/[.*+?^${}()|[\\]\\]/g, '\\$&')}\\b`).test(body) ? [i] : []);
  const parameterToSinks = [];
  for (const [category, pattern] of Object.entries(SINKS)) {
    for (const match of body.matchAll(new RegExp(pattern.source, pattern.flags))) parameters.forEach((p,i) => {
      if (new RegExp(`\\b${p.name.replace(/[.*+?^${}()|[\\]\\]/g, '\\$&')}\\b`).test(match[1])) parameterToSinks.push({ parameter:i, category, sanitized:!!SANITIZERS[category]?.test(match[1]) });
    });
  }
  const returns = [...body.matchAll(/\breturn\s+([^;]+);/g)].map(match => match[1]);
  const sourcesToReturn = Object.entries(SOURCES).filter(([,re]) => returns.some(expression => re.test(expression))).map(([category]) => category);
  return createMethodSummary({ methodId:method.id, parameters, parameterToReturn, parameterToSinks, sourcesToReturn,
    sanitizersBySink:Object.fromEntries([...new Set(parameterToSinks.map(x=>x.category))].map(category=>[category,parameterToSinks.filter(x=>x.category===category).every(x=>x.sanitized)])) });
}

module.exports = { summarizeMethod, SINKS, SANITIZERS, SOURCES };
