'use strict';

function connectionParts(text) {
  const parts = [];
  let i = 0;
  while (i < text.length) {
    while (/[\s;]/.test(text[i] || '') && i < text.length) i++;
    if (i === text.length) break;
    const start = i;
    while (i < text.length && text[i] !== '=' && text[i] !== ';') i++;
    if (text[i] !== '=') return [];
    const key = text.slice(start, i++).trim().toLowerCase();
    if (!/^[a-z][a-z ]{0,63}$/.test(key)) return [];
    while (i < text.length && /\s/.test(text[i])) i++;
    let value = '';
    if (text[i] === '"' || text[i] === "'") {
      const quote = text[i++]; let closed = false;
      while (i < text.length) {
        if (text[i] === quote) {
          if (text[i + 1] === quote) { value += quote; i += 2; continue; }
          i++; closed = true; break;
        }
        value += text[i++];
      }
      if (!closed) return [];
      while (i < text.length && /\s/.test(text[i])) i++;
      if (i < text.length && text[i] !== ';') return [];
    } else {
      const begin = i;
      while (i < text.length && text[i] !== ';') i++;
      value = text.slice(begin, i).trim();
    }
    parts.push({ key, value });
    if (parts.length > 64) return [];
  }
  return parts;
}

function literals(line, xml) {
  const result = [];
  for (let i = 0; i < line.length; i++) {
    if (line[i] !== '"' && !(xml && line[i] === "'")) continue;
    const start = i, quote = line[i], verbatim = !xml && line[i - 1] === '@';
    const interpolated = !xml && (line[i - 1] === '$' || (verbatim && line[i - 2] === '$'));
    let value = '', closed = false;
    for (i++; i < line.length; i++) {
      if (line[i] === quote) {
        if (verbatim && line[i + 1] === quote) { value += quote; i++; continue; }
        closed = true; break;
      }
      if (!xml && !verbatim && line[i] === '\\') { value += line[i] + (line[++i] || ''); continue; }
      value += line[i];
    }
    if (!closed || interpolated) continue;
    if (!xml && !verbatim) { try { value = JSON.parse('"' + value + '"'); } catch { continue; } }
    if (xml) value = value.replace(/&(quot|apos|lt|gt|amp);/g, (_, n) => ({ quot: '"', apos: "'", lt: '<', gt: '>', amp: '&' }[n]));
    result.push({ value, raw: line.slice(start, i + 1), col: start + 1 });
  }
  return result;
}

function scanDotnetSecrets(rel, raw, lines, placeholder) {
  const hits = [];
  if (!/\.(?:cs|json|config)$/i.test(rel)) return hits;
  const xml = /\.config$/i.test(rel);
  for (let line = 0; line < lines.length; line++) {
    if (lines[line].length > 4000 || (!xml && /"""/.test(lines[line]))) continue;
    for (const literal of literals(lines[line], xml)) {
      const parts = connectionParts(literal.value);
      if (!parts.some(p => /^(?:server|data source|address|addr|network address)$/.test(p.key) && p.value) ||
          !parts.some(p => /^(?:user id|uid|user|username)$/.test(p.key) && p.value)) continue;
      const passwords = parts.filter(p => /^(?:password|pwd)$/.test(p.key) && p.value &&
        !placeholder(p.value) && !/^(?:__\w+__|\{[^}]*\}|\$\([^)]*\)|%\w+%)$/.test(p.value));
      if (passwords.length) hits.push({ ruleId: 'SECRET-DOTNET-CONN-001', line: line + 1, col: literal.col, secret: literal.raw,
        redactValues: passwords.map(p => p.value), confidence: 'high', severity: 'high' });
    }
  }
  // Configuration text only, bounded tag size. Comments still expose committed
  // key material; this reports exposure, not whether the tag is active at runtime.
  if (xml && raw.length <= 1024 * 1024) {
    for (const start of raw.matchAll(/<machineKey(?=[\s/>])/g)) {
      const attrs = []; let i = start.index + start[0].length, valid = false;
      const limit = Math.min(raw.length, start.index + 8192);
      while (i < limit) {
        const separator = i;
        while (i < limit && /\s/.test(raw[i])) i++;
        if (raw[i] === '/' && raw[i + 1] === '>') { i += 2; valid = true; break; }
        if (raw[i] === '>') { i++; valid = true; break; }
        if (i === separator || attrs.length >= 64) break;
        const nameStart = i;
        while (i < limit && /[A-Za-z0-9_:.-]/.test(raw[i])) i++;
        const name = raw.slice(nameStart, i);
        while (i < limit && /\s/.test(raw[i])) i++;
        if (!name || raw[i++] !== '=') break;
        while (i < limit && /\s/.test(raw[i])) i++;
        const quote = raw[i++];
        if (quote !== '"' && quote !== "'") break;
        const valueStart = i;
        while (i < limit && raw[i] !== quote) i++;
        if (i === limit) break;
        attrs.push({ name, value: raw.slice(valueStart, i++) });
      }
      if (!valid || new Set(attrs.map(a => a.name)).size !== attrs.length) continue;
      for (const attr of attrs) {
        if (!/^(?:validationKey|decryptionKey)$/.test(attr.name) || !/^[0-9a-fA-F]{32,128}$/.test(attr.value) || attr.value.length % 2 || /^(.)\1+$/.test(attr.value)) continue;
        const line = raw.slice(0, start.index).split('\n').length;
        hits.push({ ruleId: 'SECRET-ASPNET-MACHINEKEY-001', line, endLine: line + raw.slice(start.index, i).split('\n').length - 1,
          col: start.index - raw.lastIndexOf('\n', start.index - 1), secret: attr.value, confidence: 'medium', severity: 'high' });
      }
    }
  }
  return hits;
}
module.exports = { scanDotnetSecrets };
