'use strict';
// Additive MVC/EF evidence only; this module never suppresses another rule.
const { tokenizeCSharp } = require('./parsers/csharp/lexer');
const { buildDotnetProjectIndex } = require('./dotnet/project-index');
const name = t => t?.kind === 'identifier' ? t.text.replace(/^@/, '') : null;
const joined = ts => ts.map(t => t.text).join('');
function delimiters(ts) {
  const pairs = new Map(), stack = [];
  for (let i = 0; i < ts.length; i++) {
    if (['(', '[', '{'].includes(ts[i].text)) stack.push(i);
    else if ([')', ']', '}'].includes(ts[i].text)) {
      const open = stack.pop(); if (open === undefined || ts[open].text !== {')':'(',']':'[','}':'{'}[ts[i].text]) return null;
      pairs.set(open, i);
    }
  }
  return stack.length ? null : pairs;
}
function imports(ts) {
  const result = new Set();
  for (let i = 0; i < ts.length; i++) if (ts[i].text === 'using') {
    let j = i + 1; while (j < ts.length && ![';', '(', '{'].includes(ts[j].text)) j++;
    if (ts[j]?.text === ';' && ts.slice(i + 1, j).every(t => name(t) || t.text === '.')) result.add(joined(ts.slice(i + 1, j)));
  }
  return result;
}
function split(ts, separator) {
  const parts = []; let start = 0, depth = 0;
  for (let i = 0; i < ts.length; i++) {
    if (['(', '[', '{'].includes(ts[i].text)) depth++;
    else if ([')', ']', '}'].includes(ts[i].text)) depth--;
    else if (!depth && ts[i].text === separator) { parts.push(ts.slice(start, i)); start = i + 1; }
  }
  parts.push(ts.slice(start)); return parts;
}
function interpolation(token, env) {
  // Simple string holes only, with escaped brace pairs. No custom formatting.
  if (!/^\$"[^\r\n]*"$/.test(token.text) || token.text.startsWith('$"""') || /\\/.test(token.text)) return null;
  const body = token.text.slice(2, -1); let source = null, holes = 0;
  for (let i = 0; i < body.length; i++) {
    if (body[i] === '{' && body[i + 1] === '{' || body[i] === '}' && body[i + 1] === '}') { i++; continue; }
    if (body[i] === '}') return null;
    if (body[i] !== '{') continue;
    const end = body.indexOf('}', i + 1); if (end < 0 || ++holes > 32) return null;
    const key = body.slice(i + 1, end).trim(); if (!/^@?[A-Za-z_]\w*$/.test(key)) return null;
    if (!env.has(key.replace(/^@/, ''))) return null;
    const value = env.get(key.replace(/^@/, '')); if (!value) return null;
    source ||= value.source; i = end;
  }
  return { source };
}
function valueOf(ts, env, depth = 0) {
  if (!ts.length || ts.length > 256 || depth > 16) return null;
  if (ts[0].text === '(' && delimiters(ts)?.get(0) === ts.length - 1) return valueOf(ts.slice(1, -1), env, depth + 1);
  const parts = split(ts, '+');
  if (parts.length > 1) {
    const values = parts.map(p => valueOf(p, env, depth + 1));
    return values.every(Boolean) ? { source: values.find(v => v.source)?.source || null } : null;
  }
  if (ts.length !== 1) return null;
  if (ts[0].kind === 'string') return { source: null };
  if (ts[0].kind === 'interpolated-string') return interpolation(ts[0], env);
  return name(ts[0]) && env.has(name(ts[0])) ? env.get(name(ts[0])) : null;
}
function prefix(ts, index) {
  let start = index - 1; while (start >= 0 && ![';', '{', '}'].includes(ts[start].text)) start--;
  return ts.slice(start + 1, index);
}
function knownMetadata(header, data, controller = false) {
  // Known MVC action metadata only. Unknown filters may constrain the input.
  let i = 0;
  while (header[i]?.text === '[') {
    const close = data.pairs.get(data.positions.get(header[i].start)); if (close === undefined) return null;
    const stop = header.findIndex(t => t === data.ts[close]); if (stop < 0) return null;
    const attr = joined(header.slice(i + 1, stop));
    if (!(controller && /^(?:Microsoft\.AspNetCore\.Mvc\.)?ApiController(?:Attribute)?$/.test(attr)) &&
        !/^(?:Microsoft\.AspNetCore\.Mvc\.)?(?:HttpGet|HttpPost|HttpPut|HttpDelete|HttpPatch|HttpHead|HttpOptions|Route)(?:Attribute)?(?:\(.*\))?$/.test(attr) &&
        !/^(?:Microsoft\.AspNetCore\.Authorization\.)?(?:Authorize|AllowAnonymous)(?:Attribute)?(?:\(.*\))?$/.test(attr)) return null;
    i = stop + 1;
  }
  return header.slice(i);
}
function actionParameters(method, data) {
  const at = data.positions.get(method.start), header = knownMetadata(prefix(data.ts, at), data);
  if (!header || joined(header) !== 'publicIActionResult') return null;
  const close = data.pairs.get(at + 1); if (close === undefined) return null;
  const parameters = new Map();
  for (let part of split(data.ts.slice(at + 2, close), ',')) {
    if (!part.length) continue;
    if (part[0].text === '[') {
      const end = part.findIndex(t => t.text === ']');
      if (end < 0 || !/^From(?:Query|Route|Form|Header)$/.test(joined(part.slice(1, end)))) return null;
      part = part.slice(end + 1);
    }
    if (part.length === 3 && part[1].text === '?') part = [part[0], part[2]];
    if (part.length !== 2 || !['string', 'int', 'bool'].includes(part[0].text) || !name(part[1]) || parameters.has(name(part[1]))) return null;
    parameters.set(name(part[1]), part[0].text === 'string' ? { source: { parameter: name(part[1]), offset: part[1].start } } : null);
  }
  return parameters;
}
function safeLeadingGuard(condition, env) {
  if (condition.some(t => ['=', '+=', '-=', '++', '--', 'ref', 'out', '=>'].includes(t.text))) return false;
  const used = [...env].filter(([key, value]) => value?.source && condition.some(t => name(t) === key)).map(([key]) => key);
  // Only a simple predicate call is admitted without source references.
  // Literal/constant expressions could make the following sink unreachable.
  if (!used.length) {
    const call = condition[0]?.text === '!' ? condition.slice(1) : condition;
    return call.length === 3 && !!name(call[0]) && call[1].text === '(' && call[2].text === ')';
  }
  if (used.length !== 1) return false;
  const q = used[0], expression = joined(condition);
  return expression === `string.IsNullOrEmpty(${q})` || expression === `string.IsNullOrWhiteSpace(${q})` ||
    expression === `${q}==null` || expression === `${q}==""`;
}
function methodFindings(method, data, fields, file) {
  const env = actionParameters(method, data); if (!env) return [];
  const body = data.ts.filter(t => t.start > method.bodyStart && t.end < method.bodyEnd);
  if (body.length > 4096 || body.some(t => ['=>', 'ref', 'out', 'for', 'foreach', 'while', 'do', 'try', 'catch', 'finally', 'switch', 'goto', 'unsafe', 'yield'].includes(t.text))) return [];
  // Guard-only returns are admitted at the beginning, with no source-dependent
  // validation beyond null/empty checks. All other control flow stays unknown.
  let begin = 0;
  while (body[begin]?.text === 'if') {
    const open = data.positions.get(body[begin + 1]?.start), close = data.pairs.get(open);
    if (close === undefined || !safeLeadingGuard(data.ts.slice(open + 1, close), env)) return [];
    const end = body.findIndex(t => t === data.ts[close]); let next = end + 1;
    const block = body[next]?.text === '{'; if (block) next++;
    if (body[next]?.text !== 'return') return [];
    while (next < body.length && body[next].text !== ';' && body[next].text !== '}') next++;
    if (body[next]?.text !== ';') return [];
    next++; if (block) { if (body[next]?.text !== '}') return []; next++; }
    begin = next;
  }
  const ts = body.slice(begin);
  if (ts.some(t => ['if', 'else', '{', '}', '?', '?.', '??', '&&', '||'].includes(t.text))) return [];
  const out = [];
  for (const statement of split(ts, ';')) {
    if (!statement.length) continue;
    const terminal = ['return', 'throw'].includes(statement[0].text);
    const assignments = statement.filter(t => t.text === '=');
    if (assignments.length > 1) return out;
    if (assignments.length) {
      const left = statement.slice(0, statement.indexOf(assignments[0]));
      if (!(left.length === 1 && name(left[0]) || left.length === 2 && ['string','var','int','bool'].includes(left[0].text) && name(left[1]))) return out;
    }
    for (let i = 0; i + 6 < statement.length; i++) {
      const root = name(statement[i]), set = name(statement[i + 2]);
      if (!root || statement[i - 1]?.text === '.' || env.has(root) || !fields.get(root)?.has(set) ||
          statement[i + 1].text !== '.' || statement[i + 3]?.text !== '.' || statement[i + 4]?.text !== 'FromSqlRaw' || statement[i + 5]?.text !== '(') continue;
      const open = data.positions.get(statement[i + 5].start), close = data.pairs.get(open);
      if (close === undefined) continue;
      const argument = split(data.ts.slice(open + 1, close), ',')[0];
      if (argument.length !== 1 || !name(argument[0])) continue; // Existing inline rule remains authoritative.
      const value = env.get(name(argument[0]));
      if (value?.source) {
        const sink = statement[i + 4];
        out.push({file,line:data.lineAt(sink.start),detail:`MVC parameter ${value.source.parameter} at line ${data.lineAt(value.source.offset)} reaches a local string passed to EF FromSqlRaw.`});
      }
    }
    if (terminal) break;
    const equals = statement.findIndex(t => t.text === '=');
    if (equals >= 0) {
      const left = statement.slice(0, equals), key = name(left.at(-1));
      if (left.length === 1 && key && env.has(key) || left.length === 2 && ['string', 'var'].includes(left[0].text) && key) env.set(key, valueOf(statement.slice(equals + 1), env));
      else if (key && left.length <= 2) env.set(key, null);
    }
    for (let i = 0; i < statement.length; i++) if (name(statement[i]) && ['+=', '-=', '*=', '/=', '??=', '++', '--'].includes(statement[i + 1]?.text)) env.set(name(statement[i]), null);
  }
  return out;
}
function mvcSqlFindings({files, complete = true}) {
  if (!complete) return [];
  const cs = files.filter(f => f.lang === 'csharp' && /\.cs$/i.test(f.rel));
  const candidates = cs.filter(f => /\busing\s+Microsoft\.AspNetCore\.Mvc\s*;/.test(f.code) && /\busing\s+Microsoft\.EntityFrameworkCore\s*;/.test(f.code) && /\.\s*FromSqlRaw\s*\(/.test(f.code));
  if (!candidates.length || cs.length > 1000 || cs.reduce((sum,f) => sum + Buffer.byteLength(f.code), 0) > 8 * 1024 * 1024) return [];
  const models = new Map();
  const symbols = ['Controller','ControllerBase','IActionResult','DbContext','DbSet',
    ...['HttpGet','HttpPost','HttpPut','HttpDelete','HttpPatch','HttpHead','HttpOptions','Route','ApiController','Authorize','AllowAnonymous','FromQuery','FromRoute','FromForm','FromHeader'].flatMap(s=>[s,s+'Attribute'])];
  for (const file of cs) {
    if (file.code.length > 100000) return [];
    const lex = tokenizeCSharp(file.code), ts = lex.tokens, pairs = delimiters(ts);
    if (lex.errors.length || !pairs || ts.length > 20000 || lex.regions.some(r => r.kind === 'directive') ||
        ts.some(t => t.kind === 'punctuation' && /[^\x00-\x7f]/.test(t.text)) ||
        ts.some((t,i) => ['class','struct','record','interface'].includes(t.text) && symbols.includes(name(ts[i+1]))) ||
        ts.some((t,i) => t.text === 'using' && name(ts[i+1]) && ts[i+2]?.text === '=') ||
        ts.some((t,i) => name(t) === 'FromSqlRaw' && ts[i-1]?.text !== '.')) return [];
    const starts=[0];for(let i=0;i<file.code.length;i++)if(file.code[i]==='\n')starts.push(i+1);
    const lineAt=offset=>{let lo=0,hi=starts.length;while(lo+1<hi){const mid=(lo+hi)>>>1;if(starts[mid]<=offset)lo=mid;else hi=mid;}return lo+1;};
    models.set(file.rel,{ts,pairs,positions:new Map(ts.map((t,i)=>[t.start,i])),imports:imports(ts),lineAt});
  }
  const index = buildDotnetProjectIndex(cs.map(f=>({file:f.rel,source:f.code})));
  if (index.diagnostics.truncated || index.diagnostics.fallbackFiles || index.methods.length > 512) return [];
  const types = new Map(index.types.map(t=>[t.id,t])), contexts = new Map();
  for (const type of index.types) {
    if (type.kind !== 'class' || type.ambiguous || type.partial || type.declarations.length !== 1 || !type.bases.includes('DbContext')) continue;
    const file=type.files[0],data=models.get(file);if(!data.imports.has('Microsoft.EntityFrameworkCore'))continue;
    const ts=data.ts;const begin=ts.findIndex(t=>t.start===type.declarations[0].start);let open=begin;
    while(open<ts.length&&ts[open].text!=='{')open++;
    const end=data.pairs.get(open);if(end===undefined)continue;
    const sets=new Set();let depth=0;
    for(let i=open+1;i<end;i++){
      if(ts[i].text==='{')depth++;else if(ts[i].text==='}')depth--;
      if(depth||ts[i].text!=='public'||ts[i+1]?.text!=='DbSet'||ts[i+2]?.text!=='<'||!name(ts[i+3])||ts[i+4]?.text!=='>'||!name(ts[i+5])||ts[i+6]?.text!=='{')continue;
      const close=data.pairs.get(i+6),access=joined(ts.slice(i+7,close));
      if(['get;set;','get;private set;'].map(s=>s.replaceAll(' ','')).includes(access))sets.add(name(ts[i+5]));
    }
    contexts.set(type.id,sets);
  }
  const out=[];
  for(const file of candidates){
    const data=models.get(file.rel);
    for(const method of index.methods.filter(m=>m.file===file.rel&&!m.ambiguous)){
      const owner=types.get(method.typeId);if(!owner||owner.partial||owner.ambiguous||owner.name.includes('.')||!owner.bases.some(b=>['Controller','ControllerBase'].includes(b)))continue;
      const declaration=data.ts.findIndex(t=>t.start===owner.declarations[0].start),header=knownMetadata(prefix(data.ts,declaration),data,true);
      if(!header||!['public','publicsealed'].includes(joined(header))||data.ts[declaration+2]?.text==='<')continue;
      const fields=new Map();
      for(const field of owner.fields){
        if(owner.constructorFieldTypes[field.name]!==field.type)continue;
        const resolved=index.types.filter(t=>contexts.has(t.id)&&t.name===field.type&&(t.namespace===owner.namespace||data.imports.has(t.namespace)));
        if(resolved.length===1)fields.set(field.name,contexts.get(resolved[0].id));
      }
      if(fields.size)out.push(...methodFindings(method,data,fields,file.rel));
    }
  }
  return out;
}
module.exports={mvcSqlFindings};
