'use strict';
const { maskStrings } = require('./languages');

// Deliberately small syntax subset. These checks add findings; they never
// suppress another rule or infer safety from an unsupported method body.
function context(code) {
  if (code.length > 100000 || /[^\x00-\x7f]|\x00|@"|"""|^\s*#/m.test(code)) return null;
  const mask = maskStrings(code, 'csharp');
  if (/\busing\s+\w+\s*=|\b(?:class|struct|record)\s+(?:Path|MD5|Encoding|TokenValidationParameters|ControllerBase|Process)\b/.test(mask)) return null;
  return mask;
}
function hit(code, offset, confidence = 'medium') {
  const before = code.slice(0, offset);
  return { line: before.split('\n').length, col: offset - before.lastIndexOf('\n'), confidence };
}
function controllerRanges(mask) {
  const blocks = new Map(), stack = [];
  for (let i = 0; i < mask.length; i++) {
    if (mask[i] === '{') { if (stack.length >= 64) return []; stack.push(i); }
    if (mask[i] === '}') { const open = stack.pop(); if (open === undefined) return []; blocks.set(open, i); }
  }
  if (stack.length) return [];
  const types = [];
  for (const m of mask.matchAll(/\b(?:class|struct|record)\s+\w+[^{};]{0,500}\{/g)) {
    const open = m.index + m[0].length - 1;
    types.push({ open, end: blocks.get(open), controller: /^class\s+\w+\s*:\s*ControllerBase\s*\{$/.test(m[0]) });
  }
  return types;
}
function simpleMethods(code, mask, singleReturn = true) {
  const out = [];
  const re = /\bpublic\s+(?:static\s+)?(?:IActionResult|string)\s+\w+\s*\(([^(){};]{0,1000})\)\s*\{([^{}]{0,4000})\}/g;
  for (const m of mask.matchAll(re)) {
    const open = m.index + m[0].indexOf('{');
    const body = code.slice(open + 1, m.index + m[0].length - 1);
    // A single return leaves no earlier guard, assignment or helper effect to
    // interpret. Explicit framework-bound parameters are local to this match.
    if (singleReturn && !/^\s*return\s+[^;]+;\s*$/.test(body)) continue;
    const prefixStart = Math.max(mask.lastIndexOf('{', m.index), mask.lastIndexOf('}', m.index)) + 1;
    out.push({ params: m[1], body, start: open + 1, declaration: m.index,
      action: /^public\s+IActionResult\b/.test(m[0]) && !/\b(?:NonAction|NonActionAttribute)\b/.test(mask.slice(prefixStart, m.index)) });
  }
  return out;
}
function requestReturns(kind, { code }) {
  const mask = context(code);
  if (!mask || !/\busing\s+Microsoft\.AspNetCore\.Mvc\s*;/.test(mask) ||
      !/\bclass\s+\w+\s*:\s*ControllerBase\b/.test(mask)) return [];
  if (kind === 'command' && !/\busing\s+System\.Diagnostics\s*;/.test(mask)) return [];
  // Custom implementations of framework methods make name matching ambiguous.
  if (/\b\w+\s+(?:Redirect|PhysicalFile)\s*\(/.test(mask.replace(/\breturn\b/g, ''))) return [];
  const types = controllerRanges(mask);
  const out = [];
  for (const m of simpleMethods(code, mask, kind !== 'command')) {
    const owner = types.filter(t => t.open < m.declaration && t.end > m.start).at(-1);
    if (!m.action || !owner?.controller) continue;
    const params = [...m.params.matchAll(/\[From(?:Query|Route|Form|Header)\]\s+string\s+(\w+)\s*(?=,|$)/g)].map(x => x[1]);
    const expr = kind === 'command'
      ? /^\s*(?:var\s+\w+\s*=\s*)?Process\.Start\s*\(\s*"(?:\/bin\/sh|bash)"\s*,\s*("(?:[^"\\]|\\.)*")\s*\+\s*(\w+)\s*\+\s*("(?:[^"\\]|\\.)*")\s*\)\s*;\s*return\s+Ok\s*\(\s*\)\s*;\s*$/
      : kind === 'redirect'
      ? /^\s*return\s+Redirect\s*\(\s*(\w+)\s*\)\s*;\s*$/
      : /^\s*return\s+PhysicalFile\s*\(\s*Path\.Combine\s*\(\s*"(?:[^"\\]|\\.)*"\s*,\s*(\w+)\s*\)\s*,\s*"(?:[^"\\]|\\.)*"\s*\)\s*;\s*$/;
    const match = m.body.match(expr);
    if (!match) continue;
    if (kind === 'command') {
      // Accept only escapes shared by JSON and ordinary C# strings. The
      // parameter must be inside the -c command, not a positional argument.
      let prefix, suffix;
      try { prefix = JSON.parse(match[1]); suffix = JSON.parse(match[3]); } catch { continue; }
      if (!/^-c "[^"\\]*$/.test(prefix) || suffix !== '"' || !params.includes(match[2])) continue;
    } else if (!params.includes(match[1])) continue;
    out.push(hit(code, m.start + m.body.indexOf(kind === 'command' ? 'Process.Start' : kind === 'redirect' ? 'Redirect' : 'PhysicalFile')));
  }
  return out;
}
function passwordMd5({ code }) {
  const mask = context(code);
  if (!mask || !/\busing\s+System\.Security\.Cryptography\s*;/.test(mask)) return [];
  const out = [];
  for (const m of simpleMethods(code, mask)) {
    const params = [...m.params.matchAll(/(?:^|,)\s*string\s+(pw|password|passwd)\s*(?=,|$)/g)].map(x => x[1]);
    const match = m.body.match(/^\s*return\s+(?:System\.)?BitConverter\.ToString\s*\(\s*MD5\.Create\s*\(\s*\)\.ComputeHash\s*\(\s*Encoding\.UTF8\.GetBytes\s*\(\s*(\w+)\s*\)\s*\)\s*\)\s*;\s*$/);
    if (match && params.includes(match[1])) out.push(hit(code, m.start + m.body.indexOf('MD5')));
  }
  return out;
}
function unsignedJwt({ code }) {
  const mask = context(code);
  if (!mask || !/\busing\s+Microsoft\.IdentityModel\.Tokens\s*;/.test(mask)) return [];
  const out = [];
  for (const m of mask.matchAll(/\b\w+\.TokenValidationParameters\s*=\s*new\s+TokenValidationParameters\s*\{([^{}]{0,2000})\}\s*;/g)) {
    const members = m[1].split(',').map(x => x.trim()).filter(Boolean);
    const seen = new Set();
    const simple = members.every(member => {
      const value = member.match(/^(ValidateIssuer|ValidateAudience|ValidateLifetime|RequireSignedTokens|ValidateIssuerSigningKey)\s*=\s*(true|false)$/);
      if (!value || seen.has(value[1])) return false;
      seen.add(value[1]); return true;
    });
    const receiver = m[0].slice(0, m[0].indexOf('.'));
    const after = mask.slice(m.index + m[0].length);
    const immediateSecureOverride = new RegExp(`^\\s*${receiver}\\.TokenValidationParameters\\.RequireSignedTokens\\s*=\\s*true\\s*;`).test(after);
    if (simple && !immediateSecureOverride && members.some(x => /^RequireSignedTokens\s*=\s*false$/.test(x))) out.push(hit(code, m.index));
  }
  return out;
}
module.exports = { requestReturns, passwordMd5, unsignedJwt };
