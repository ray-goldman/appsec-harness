'use strict';
// A source-only proof for one compile-time string expression, not a C# binder.
// Unsupported build inputs, bindings or interpolation syntax retain the warning.
const path = require('node:path').posix;
const { parseCSharp } = require('./parsers/csharp/parser');
const { tokenFile, name, text } = require('./csharp-proof-index');
// Reserved tokens are not type identifiers without @. In particular, `this`
// denotes an instance even if an unrelated source type is named @this.
const RESERVED = new Set(('abstract as base bool break byte case catch char checked class const continue decimal default delegate do double else enum event explicit extern false finally fixed float for foreach goto if implicit in int interface internal is lock long namespace new null object operator out override params private protected public readonly ref return sbyte sealed short sizeof stackalloc static string struct switch this throw true try typeof uint ulong unchecked unsafe ushort using virtual void volatile while').split(' '));
const CONTEXTUAL = new Set(('add allows alias and ascending args async await by closed descending dynamic equals extension field file from get global group init into join let managed nameof nint not notnull nuint on or orderby partial record remove required safe scoped select set unmanaged union value var when where with yield').split(' '));

function projectScope(projects, files) {
  if (projects.length !== 1 || !projects[0].file.endsWith('.csproj')) return false;
  const project = projects[0], base = path.dirname(project.file);
  if (project.raw.length > 20000 || files.some(f => {
    const relative = path.relative(base, f.file);
    return relative.startsWith('../') || path.isAbsolute(relative) || !relative.endsWith('.cs') ||
      relative.split('/').some(part=>part.startsWith('.') || /^(?:bin|obj|node_modules|bower_components|jspm_packages|packages|vendor)$/i.test(part));
  })) return false;
  let xml = project.raw.replace(/^\s*<Project Sdk="Microsoft\.NET\.Sdk(?:\.Web)?">/, '').replace(/<\/Project>\s*$/, '');
  // No conditions, imports, custom compile items, references or build targets.
  xml = xml.replace(/<(TargetFramework|Nullable|ImplicitUsings|TreatWarningsAsErrors|RootNamespace)>[A-Za-z0-9_.-]+<\/\1>/g, '')
    .replace(/<\/?(?:PropertyGroup|ItemGroup)>/g, '')
    .replace(/<PackageReference Include="Microsoft\.Data\.Sqlite" Version="\[?\d+\.\d+\.\d+\]?"\s*\/>/g, '');
  return !xml.trim();
}

function holes(token) {
  if (token.kind !== 'interpolated-string') return null;
  const quote = token.text.match(/^\$("{3,}|"(?=[^"]|$))/)?.[1];
  if (!quote || !token.text.endsWith(quote)) return null;
  const body = token.text.slice(1 + quote.length, -quote.length), result = [];
  // No escaped delimiters, format/alignment clauses, expressions or nested holes.
  if (quote.length===1 && body.includes('\\') || body.includes('{{') || body.includes('}}')) return null;
  let end = 0;
  for (const match of body.matchAll(/\{\s*([A-Za-z_]\w*)\.([A-Za-z_]\w*)\s*\}/g)) {
    if (/[{}]/.test(body.slice(end, match.index))) return null;
    if([match[1],match[2]].some(word=>RESERVED.has(word)||CONTEXTUAL.has(word))) return null;
    result.push({ type: match[1], member: match[2] }); end = match.index + match[0].length;
  }
  return result.length && !/[{}]/.test(body.slice(end)) ? result : null;
}

function createCSharpConstMemberProof(sources, { complete = true, projects = [], projectComplete = true } = {}) {
  const decline = () => false;
  const inputs = sources.filter(s => /\.cs$/i.test(s.file));
  if (!complete || !projectComplete || inputs.length > 1000 || inputs.reduce((n,s)=>n+Buffer.byteLength(s.raw),0) > 8*1024*1024 || !projectScope(projects, inputs)) return decline;
  const files = [], types = [], declarations = new Set();
  for (const source of inputs) {
    if (source.raw.length > 100000 || !parseCSharp(source.raw).complete) return decline;
    const lex = tokenFile(source.raw); if (!lex) return decline;
    const { ts, pairs } = lex;
    if (ts.some((t,i) => t.text === 'extern' || t.text === 'global' && ts[i+1]?.text === 'using')) return decline;
    const imports = [], namespaces = []; let fileNamespace = '';
    for (let i=0;i<ts.length;i++) {
      if (ts[i].text === 'using' && ts[i+1]?.text !== 'var' && ts[i+1]?.text !== '(') {
        let j=i+1; while (name(ts[j]) || ts[j]?.text === '.') j++;
        if (ts[i+1]?.text === 'static' || ts[j]?.text === '=') return decline;
        if (ts[j]?.text === ';') imports.push(text(ts.slice(i+1,j)));
      }
      if (ts[i].text !== 'namespace') continue;
      let j=i+1; while (name(ts[j]) || ts[j]?.text === '.') j++;
      const ns = text(ts.slice(i+1,j)); if (!ns) return decline;
      if (ts[j]?.text === ';') { if (fileNamespace || namespaces.length) return decline; fileNamespace=ns; }
      else if (ts[j]?.text === '{' && pairs.has(j)) namespaces.push({ ns, start:j, end:pairs.get(j) });
      else return decline;
    }
    if (namespaces.some((n,i)=>namespaces.some((m,j)=>i!==j && m.start<n.start && m.end>n.end))) return decline;
    if(fileNamespace && namespaces.length) return decline;
    const file = { ...source, ...lex, imports, namespace:fileNamespace, blockNamespaces:namespaces.length, types:[] }; files.push(file);
    for(let i=0;i<ts.length;i++) {
      if (!['class','interface','record','struct','enum'].includes(ts[i].text) || !name(ts[i+1])) continue;
      let open=i+2; while(open<ts.length && !['{',';'].includes(ts[open].text)) open++;
      const close=ts[open]?.text==='{'?pairs.get(open):open; if(close===undefined) return decline;
      const ns=namespaces.find(n=>n.start<i&&n.end>i)?.ns || fileNamespace;
      const type={name:name(ts[i+1]),kind:ts[i].text,namespace:ns,file,start:i,open,close,header:ts.slice(i+2,open),members:new Set()};
      let prefix=i-1; while(prefix>=0 && ![';','{','}'].includes(ts[prefix].text)) prefix--;
      type.unsupported=ts[i+2]?.text==='<' || ts.slice(prefix+1,i).some(t=>['partial','file'].includes(t.text)) || types.some(t=>t.file===file&&t.open<i&&t.close>i);
      declarations.add(ts[i+1]); types.push(type); file.types.push(type);
      if(type.unsupported || type.kind!=='class') continue;
      let segment=open+1;
      for(let j=open+1;j<close;j++) {
        if(ts[j].text==='{') { j=pairs.get(j); segment=j+1; continue; }
        if(ts[j].text!==';') continue;
        const part=ts.slice(segment,j), at=part.findIndex(t=>t.text==='const'); segment=j+1;
        if(at<0 || !part.slice(0,at).some(t=>['public','internal'].includes(t.text)) || part.slice(0,at).some(t=>!['public','internal'].includes(t.text))) continue;
        if(part[at+1]?.text!=='string' || !name(part[at+2]) || part[at+3]?.text!=='=') continue;
        const rhs=part.slice(at+4);
        if(rhs.length && rhs.length<=64 && rhs.every((t,k)=>k%2?t.text==='+':t.kind==='string'&&!t.text.endsWith('u8')) && rhs.length%2) type.members.add(name(part[at+2]));
      }
    }
  }
  const namespaces=new Set(types.map(t=>t.namespace));
  // External imports/build extensions cannot supply a competing source binding.
  if(files.some(f=>f.imports.some(ns=>!namespaces.has(ns)&&!/^System(?:\.|$)|^Microsoft\.(?:AspNetCore|Extensions|Data\.Sqlite)(?:\.|$)/.test(ns)))) return decline;
  const byName=new Map(); for(const type of types) { if(!byName.has(type.name))byName.set(type.name,[]);byName.get(type.name).push(type); }
  const shadowCache=new Map();
  function shadowed(typeName) {
    if(shadowCache.has(typeName)) return shadowCache.get(typeName);
    const unknown=files.some(f=>f.ts.some((t,i)=>{
      if(name(t)!==typeName || declarations.has(t)) return false;
      const next=f.ts[i+1], previous=f.ts[i-1];
      if(next?.text==='.') return false;
      // Admit explicit type uses only. Unknown declaration/pattern contexts
      // cannot establish a binding, even when their next token is a keyword.
      const typePosition=['public','private','protected','internal','static','readonly','volatile','const','async','virtual','override','sealed','new','ref','out','in','(', ',', ';','{','}','[',']'].includes(previous?.text);
      if(typePosition && name(next) && !['and','or','when','in'].includes(next.text) &&
        [';', '=', ',', ')', '(', '{', '=>', '['].includes(f.ts[i+2]?.text)) return false;
      if(next?.text==='(' && (previous?.text==='new' ||
        ['public','private','protected','internal','static'].includes(previous?.text) &&
        f.types.some(type=>type.name===typeName && type.open<i && type.close>i))) return false;
      return true;
    }));
    shadowCache.set(typeName,unknown); return unknown;
  }
  const proved=new Map();
  for(const file of files) {
    // Imports inside block namespaces need a scoped binder; a file-wide union
    // could resolve a mutable framework value as an unrelated source type.
    if(file.blockNamespaces) continue;
    // Other opaque holes might introduce bindings (for example out variables).
    if(file.ts.some(t=>t.kind==='interpolated-string'&&!holes(t))) continue;
    const ts=file.ts;
    for(let i=0;i+4<ts.length;i++) {
      if(text(ts.slice(i,i+3))!=='.CommandText=') continue;
      const interpolated=ts[i+3], references=holes(interpolated);
      if(!references || ts[i+4]?.text!==';') continue;
      const owner=file.types.filter(t=>t.open<i&&t.close>i);
      // Default interface bodies can inherit mutable framework properties;
      // non-class owners need a different binding model and retain warnings.
      if(owner.length!==1 || owner[0].kind!=='class' || owner[0].unsupported) continue;
      // A source or unknown base class may hide a type name with an inherited member.
      const header=owner[0].header;
      // Only a flat list of simple interface identifiers is supported. Do not
      // reinterpret namespace components or primary-constructor expressions.
      if(header.length && (header[0].text!==':' || header.length%2!==0 ||
        header.slice(1).some((t,j)=>j%2?t.text!==',':!name(t)||RESERVED.has(t.text)))) continue;
      const bases=header.filter((t,j)=>j%2===1);
      if(header.some(t=>t.text===':') && bases.some(t=>{
        const declared=types.filter(type=>type.name===name(t));
        return declared.length!==1 || declared[0].kind!=='interface' || declared[0].unsupported ||
          !(declared[0].namespace===file.namespace || file.imports.includes(declared[0].namespace));
      })) continue;
      if(!references.every(ref=>{
        const candidates=byName.get(ref.type)||[]; if(candidates.length!==1 || shadowed(ref.type)) return false;
        const type=candidates[0];
        return !type.unsupported && type.members.has(ref.member) && (type.namespace===file.namespace || file.imports.includes(type.namespace));
      })) continue;
      const line=file.raw.slice(0,ts[i].start).split(/\r?\n/).length;
      // A single warning may represent multiple SQL sinks on the same line.
      const lineStart=file.raw.lastIndexOf('\n',ts[i].start-1)+1, nextLine=file.raw.indexOf('\n',ts[i].start);
      const sameLine=ts.filter(t=>t.start>=lineStart && (nextLine<0 || t.start<nextLine));
      if(sameLine.filter(t=>['CommandText','SqlCommand','FromSqlRaw','ExecuteSqlRaw','ExecuteSqlRawAsync','SqlQueryRaw'].includes(t.text)).length!==1) continue;
      if(!proved.has(file.file))proved.set(file.file,new Set()); proved.get(file.file).add(line);
    }
  }
  return (file,line)=>proved.get(file)?.has(line)||false;
}
module.exports={createCSharpConstMemberProof};
