'use strict';
// Bounded TOML subset for Cargo metadata. Never execute Cargo or recover guessed values after an error.
const own = (obj, key) => Object.hasOwn(obj, key);
const forbidden = new Set(['__proto__', 'prototype', 'constructor']);

function readToml(raw) {
  let i = 0, line = 1, steps = 0;
  const locations = new WeakMap(), explicit = new WeakSet(), dotted = new WeakSet(), sealed = new WeakSet(), tableArrays = new WeakSet();
  const object = () => { const o = Object.create(null); locations.set(o, new Map()); return o; };
  const root = object(); let current = root;
  const fail = (code) => { const error = new Error(code); error.line = line; throw error; };
  const tick = () => { if (++steps > 250000) fail('TOML item limit exceeded'); };
  const advance = () => { const ch = raw[i++]; if (ch === '\n') line++; return ch; };
  function space(multiline = false) {
    while (i < raw.length) {
      if (raw[i] === ' ' || raw[i] === '\t' || (multiline && (raw[i] === '\r' || raw[i] === '\n'))) advance();
      else if (raw[i] === '#') { while (i < raw.length && raw[i] !== '\n') advance(); }
      else break;
    }
  }
  function string() {
    const q = advance(); let text = '';
    if (raw.slice(i, i + 2) === q + q) fail('Multiline strings are outside the supported TOML subset');
    while (i < raw.length) {
      const ch = advance();
      if (ch === q) return text;
      if (/[\u0000-\u0008\u000a-\u001f\u007f]/.test(ch)) fail('Invalid control character in string');
      if (ch !== '\\' || q === "'") { text += ch; continue; }
      const escaped = advance();
      const escapes = { b:'\b', t:'\t', n:'\n', f:'\f', r:'\r', '"':'"', '\\':'\\' };
      if (own(escapes, escaped)) text += escapes[escaped];
      else if (escaped === 'u' || escaped === 'U') {
        const n = escaped === 'u' ? 4 : 8, hex = raw.slice(i, i + n);
        if (hex.length !== n || !/^[a-fA-F0-9]+$/.test(hex)) fail('Invalid Unicode escape');
        const point = Number.parseInt(hex,16);
        if (point > 0x10ffff || (point >= 0xd800 && point <= 0xdfff)) fail('Invalid Unicode scalar');
        text += String.fromCodePoint(point); i += n;
      } else fail('Unsupported string escape');
    }
    fail('Unterminated string');
  }
  function keys() {
    const parts = [];
    do {
      space(); tick();
      let key;
      if (raw[i] === '"' || raw[i] === "'") key = string();
      else { const start = i; while (i < raw.length && /[A-Za-z0-9_-]/.test(raw[i])) i++; key = raw.slice(start,i); if (!key) fail('Invalid key'); }
      if (forbidden.has(key)) fail('Unsupported reserved key');
      parts.push(key); if (parts.length > 24) fail('TOML key depth limit exceeded');
      space(); if (raw[i] !== '.') break; i++;
    } while (i < raw.length);
    return parts;
  }
  function descend(obj, key, allowArray) {
    if (!own(obj,key)) obj[key] = object();
    let next = obj[key];
    if (allowArray && tableArrays.has(next)) next = next.at(-1);
    if (!next || typeof next !== 'object' || Array.isArray(next) || sealed.has(next)) fail('Conflicting table definition');
    return next;
  }
  function assign(obj, parts, val, at) {
    for (const key of parts.slice(0,-1)) {obj = descend(obj,key,false);dotted.add(obj);}
    const key = parts.at(-1); if (own(obj,key)) fail('Duplicate key');
    obj[key] = val; locations.get(obj).set(key,at);
  }
  function value(depth = 0) {
    tick(); if (depth > 24) fail('TOML value depth limit exceeded');
    space();
    if (raw[i] === '"' || raw[i] === "'") return string();
    if (raw[i] === '[') {
      i++; const result = []; space(true);
      while (raw[i] !== ']') {
        if (i >= raw.length) fail('Unterminated array');
        result.push(value(depth+1)); space(true);
        if (raw[i] === ']') break;
        if (advance() !== ',') fail('Missing array comma'); space(true);
      }
      i++; return result;
    }
    if (raw[i] === '{') {
      i++; const result = object(); space();
      while (raw[i] !== '}') {
        if (i >= raw.length || raw[i] === '\n' || raw[i] === '\r') fail('Unsupported inline table');
        const at = line, parts = keys(); if (advance() !== '=') fail('Expected equals');
        assign(result,parts,value(depth+1),at); space();
        if (raw[i] === '}') break;
        if (advance() !== ',') fail('Missing inline table comma'); space();
      }
      i++; sealed.add(result); return result;
    }
    const start = i; while (i < raw.length && !/[\s,#\]}]/.test(raw[i])) i++;
    const bare = raw.slice(start,i);
    if (bare === 'true' || bare === 'false') return bare === 'true';
    if (/^[+-]?(?:0|[1-9][0-9]*(?:_[0-9]+)*)$/.test(bare)) {
      const n = Number(bare.replaceAll('_','')); if (!Number.isSafeInteger(n)) fail('Integer outside supported range'); return n;
    }
    fail('Unsupported or invalid TOML value');
  }
  try {
    if (typeof raw !== 'string' || Buffer.byteLength(raw) > 1024*1024) fail('TOML byte limit exceeded');
    if (raw.startsWith('\ufeff')) i++;
    while (i < raw.length) {
      space(true); if (i >= raw.length) break; tick();
      if (raw[i] === '[') {
        i++; const array = raw[i] === '['; if (array) i++;
        const parts = keys(); if (advance() !== ']' || (array && advance() !== ']')) fail('Invalid table header');
        current = root;
        for (const key of parts.slice(0,-1)) current = descend(current,key,true);
        const key = parts.at(-1);
        if (array) {
          if (!own(current,key)) {current[key] = [];tableArrays.add(current[key]);}
          if (!tableArrays.has(current[key])) fail('Conflicting array table');
          const next = object(); current[key].push(next); current = next;
        } else {
          current = descend(current,key,false);
          if (explicit.has(current)||dotted.has(current)) fail('Duplicate table'); explicit.add(current);
        }
      } else {
        const at = line, parts = keys(); if (advance() !== '=') fail('Expected equals');
        assign(current,parts,value(),at);
      }
      space(); if (i < raw.length && raw[i] !== '\r' && raw[i] !== '\n') fail('Unexpected trailing input');
    }
    return { root, locations, diagnostics: [] };
  } catch (error) {
    return { root: null, locations, diagnostics: [{ line: error.line || line, code: 'cargo-toml-unsupported', message: error.message }] };
  }
}

module.exports = { readToml };
