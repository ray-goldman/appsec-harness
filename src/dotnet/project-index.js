'use strict';
const { parseCSharp } = require('../parsers/csharp/parser');
const { tokenizeCSharp } = require('../parsers/csharp/lexer');

function findOwners(source,ast,tokens) {
  const pairs=new Map(),stack=[];
  for(let i=0;i<tokens.length;i++) {
    if(tokens[i].text==='{') stack.push(i);
    else if(tokens[i].text==='}') {const open=stack.pop();if(open!==undefined) pairs.set(open,i);}
  }
  const prefix=i=>{
    let start=i-1;
    while(start>=0&&![';','{','}'].includes(tokens[start].text)) start--;
    return tokens.slice(start+1,i).map(t=>t.text);
  };
  const types=[],namespaces=[];
  for(let i=0;i<tokens.length-1;i++) {
    if(tokens[i].text==='namespace') {
      let j=i+1,name='';
      while(j<tokens.length&&(tokens[j].kind==='identifier'||tokens[j].text==='.')) name+=tokens[j++].text.replace(/^@/,'');
      if(tokens[j]?.text===';' || tokens[j]?.text==='{'&&pairs.has(j)) namespaces.push({name,start:tokens[j].start,end:tokens[j].text===';'?source.length:tokens[pairs.get(j)].end});
    }
    if(!['class','struct','interface','record'].includes(tokens[i].text) || tokens[i+1].kind!=='identifier') continue;
    // Record class/struct names have a second keyword; avoid duplicate owners.
    if(tokens[i].text==='record' && ['class','struct'].includes(tokens[i+1].text)) continue;
    let open=i+2;while(open<tokens.length&&!['{',';'].includes(tokens[open].text)) open++;
    if(tokens[open]?.text==='{'&&pairs.has(open)) {
      const close=pairs.get(open),fields=[];let segment=open+1,depth=0;
      for(let k=open+1;k<close;k++) {
        if(tokens[k].text==='{') depth++;
        else if(tokens[k].text==='}') {depth--;if(depth===0) segment=k+1;}
        else if(tokens[k].text===';'&&depth===0) {
          const part=tokens.slice(segment,k),ids=part.filter(t=>t.kind==='identifier'),texts=part.map(t=>t.text);
          const skip=new Set(['public','private','protected','internal','static','readonly','const','volatile','new','event']);
          const useful=ids.filter(t=>!skip.has(t.text));
          if(!texts.includes('=')&&!texts.includes('(')&&useful.length===2&&part.every(t=>t.kind==='identifier'||t.text==='.'||skip.has(t.text))) fields.push({name:useful[1].text.replace(/^@/,''),type:useful[0].text.replace(/^@/,''),static:texts.includes('static')});
          segment=k+1;
        }
      }
      const header=tokens.slice(i+2,open),colon=header.findIndex(t=>t.text===':');
      const bases=colon<0?[]:header.slice(colon+1).map(t=>t.text).join('').split(',').filter(name=>/^[A-Za-z_][\w.]*$/.test(name));
      types.push({kind:tokens[i].text,bases,name:tokens[i+1].text.replace(/^@/,''),start:tokens[i].start,bodyStart:tokens[open].start,bodyEnd:tokens[close].end,partial:prefix(i).includes('partial'),unsupported:tokens[i+2]?.text==='<',fields});
    }
  }
  const parsedMethods=ast.methods.map(method=>{
    const owners=types.filter(t=>method.start>=t.bodyStart&&method.end<=t.bodyEnd).sort((a,b)=>a.start-b.start);
    const owner=owners.at(-1);
    const ns=namespaces.filter(n=>method.start>=n.start&&method.end<=n.end).sort((a,b)=>a.start-b.start).map(n=>n.name).join('.');
    const nameIndex=tokens.findIndex(t=>t.start===method.start);
    const modifiers=prefix(nameIndex);
    const header=tokens.filter(t=>t.start>=method.start&&t.start<method.bodyStart);
    const constructor=owner?.name===method.name;
    const unsupported=owners.some(o=>o.unsupported)||modifiers.some(t=>['virtual','override','abstract'].includes(t))||header.some(t=>['=',':','params','this','ref','out','in','[','<'].includes(t.text))||
      ast.methods.some(other=>other!==method&&other.bodyStart<method.start&&other.bodyEnd>=method.end);
    return {...method,namespace:ns,typeName:owners.map(t=>t.name).join('.'),ownerResolved:!!owner,ownerStart:owner?.start,partial:owner?.partial,unsupported,
      constructor,visibility:['public','protected','internal','private'].find(v=>modifiers.includes(v))||'private',static:modifiers.includes('static'),
      fields:owner?.fields||[],body:source.slice(method.bodyStart+1,method.bodyEnd-1)};
  });
  const typeRecords=types.map(type=>{
    const owners=types.filter(t=>type.bodyStart>=t.bodyStart&&type.bodyEnd<=t.bodyEnd).sort((a,b)=>a.start-b.start);
    const ns=namespaces.filter(n=>type.start>=n.start&&type.bodyEnd<=n.end).sort((a,b)=>a.start-b.start).map(n=>n.name).join('.');
    return {...type,namespace:ns,typeName:owners.map(t=>t.name).join('.'),ownerStart:owners[0]?.start};
  });
  return {methods:parsedMethods,types:typeRecords};
}

function buildDotnetProjectIndex(files) {
  const methods=[],types=new Map();let bytes=0,fallbackFiles=0,truncated=false;
  for(const entry of files) {
    const file=entry.file||entry.rel,source=entry.source??entry.raw??entry.code;
    if(!file||typeof source!=='string'||!/\.cs$/i.test(file)) continue;
    bytes+=Buffer.byteLength(source);
    if(bytes>100*1024*1024||source.length>2*1024*1024||methods.length>=50000) {fallbackFiles++;truncated=true;continue;}
    const ast=entry.ast||parseCSharp(source);if(!ast.complete) {fallbackFiles++;continue;}
    const tokens=tokenizeCSharp(source).tokens;
    const parsed=findOwners(source,ast,tokens);
    for(const declaration of parsed.types) {
      const typeId=[declaration.namespace,declaration.typeName].filter(Boolean).join('.');
      if(!types.has(typeId)) types.set(typeId,{id:typeId,kind:declaration.kind,bases:declaration.bases,namespace:declaration.namespace,name:declaration.typeName,declarations:new Map()});
      types.get(typeId).declarations.set(file+':'+declaration.start,{file,start:declaration.start,partial:declaration.partial,fields:declaration.fields||[]});
    }
    for(const m of parsed.methods) {
      if(!m.ownerResolved) continue;
      if(methods.length>=50000) {truncated=true;break;}
      const typeId=[m.namespace,m.typeName].filter(Boolean).join('.');
      if(!types.has(typeId)) types.set(typeId,{id:typeId,namespace:m.namespace,name:m.typeName,declarations:new Map()});
      const signature=m.parameters.map(p=>(p.type||'?').replace(/\s+/g,'')).join(',');
      methods.push({id:typeId+'.'+m.name+'/'+m.parameters.length+'('+signature+')',file,namespace:m.namespace,typeId,name:m.name,arity:m.parameters.length,parameterTypes:m.parameters.map(p=>p.type),parameters:m.parameters,visibility:m.visibility,static:m.static,unsupported:m.unsupported,start:m.start,end:m.end,startLine:m.startLine,bodyStart:m.bodyStart,bodyEnd:m.bodyEnd,bodyLine:source.slice(0,m.bodyStart+1).split(/\r?\n/).length,body:m.body});
    }
  }
  const counts=new Map();
  for(const method of methods) counts.set(method.id,(counts.get(method.id)||0)+1);
  const methodsByType=new Map();
  for(const method of methods) {
    if(!methodsByType.has(method.typeId)) methodsByType.set(method.typeId,[]);
    methodsByType.get(method.typeId).push(method);
  }
  for(const type of types.values()) {
    type.declarations=[...type.declarations.values()];
    type.files=[...new Set(type.declarations.map(d=>d.file))].sort();
    type.partial=type.declarations.every(d=>d.partial);
    type.ambiguous=type.declarations.length>1&&!type.partial;
    type.fields=type.declarations.flatMap(d=>d.fields);
    type.constructorFieldTypes={};
    const simpleName=type.name.split('.').at(-1);
    for(const ctor of (methodsByType.get(type.id)||[]).filter(m=>m.name===simpleName&&!m.unsupported)) {
      const ts=tokenizeCSharp(ctor.body).tokens;
      for(const field of type.fields) for(const parameter of ctor.parameters) {
        if((parameter.type||'').replace(/\s+/g,'')!==field.type) continue;
        const assignment=ts.some((t,i)=>t.text===field.name&&ts[i+1]?.text==='='&&ts[i+2]?.text===parameter.name||t.text==='this'&&ts[i+1]?.text==='.'&&ts[i+2]?.text===field.name&&ts[i+3]?.text==='='&&ts[i+4]?.text===parameter.name);
        if(assignment) type.constructorFieldTypes[field.name]=field.type;
      }
    }
  }
  for(const method of methods) method.ambiguous=counts.get(method.id)>1||types.get(method.typeId).ambiguous;
  const methodLookup=new Map();
  for(const method of methods) {
    const key=JSON.stringify([method.typeId,method.name,method.arity]);
    if(!methodLookup.has(key)) methodLookup.set(key,[]);
    methodLookup.get(key).push(method);
  }
  const registrations=new Map();
  for(const entry of files) {
    const source=entry.source||entry.raw||entry.code||'';if(typeof source!=='string') continue;
    const ts=tokenizeCSharp(source).tokens;
    for(let i=0;i+3<ts.length;i++) if(['AddScoped','AddTransient','AddSingleton'].includes(ts[i].text)&&ts[i+1].text==='<') {
      let depth=0,comma=-1,end=-1;
      for(let j=i+2;j<ts.length;j++) {if(ts[j].text==='<')depth++;else if(ts[j].text==='>'){if(depth===0){end=j;break;}depth--;}else if(ts[j].text===','&&depth===0)comma=j;}
      if(comma<0||end<0)continue;
      const simple=x=>x.length&&x.every((t,n)=>t.kind==='identifier'||t.text==='.'&&n>0&&n<x.length-1)?x.map(t=>t.text.replace(/^@/,'')).join(''):null;
      const iface=simple(ts.slice(i+2,comma)),impl=simple(ts.slice(comma+1,end));if(!iface||!impl)continue;
      if(!registrations.has(iface))registrations.set(iface,new Set());registrations.get(iface).add(impl);
    }
  }
  const typeIdsBySuffix=new Map();
  for(const typeId of types.keys()) {
    const parts=typeId.split('.');
    for(let i=0;i<parts.length;i++) {
      const suffix=parts.slice(i).join('.');
      if(!typeIdsBySuffix.has(suffix))typeIdsBySuffix.set(suffix,[]);
      typeIdsBySuffix.get(suffix).push(typeId);
    }
  }
  const resolveType=(name,namespace)=>{
    if(types.has(name)) return name;
    const local=namespace?namespace+'.'+name:null;
    if(local&&types.has(local)) return local;
    const matches=typeIdsBySuffix.get(name)||[];
    return matches.length===1?matches[0]:null;
  };
  const resolvedRegistrations=new Map();
  for(const [iface,implementations] of registrations) {
    const resolved=[...implementations].map(implementation=>resolveType(implementation,'')||'unresolved:'+implementation);
    const target=resolveType(iface,'');
    if(target&&resolved.length) resolvedRegistrations.set(target,[...new Set(resolved)].sort());
  }
  const implementers=new Map();
  for(const type of types.values()) {
    if(type.ambiguous||type.kind!=='class')continue;
    for(const base of type.bases||[]) {
      const target=resolveType(base,type.namespace);
      if(!target||types.get(target).kind!=='interface')continue;
      if(!implementers.has(target))implementers.set(target,[]);
      implementers.get(target).push(type.id);
    }
  }
  for(const type of types.values()) for(const field of type.fields) {
    const declared=type.constructorFieldTypes[field.name];if(!declared) continue;
    const iface=resolveType(declared,type.namespace),implementations=iface&&(resolvedRegistrations.get(iface)||implementers.get(iface));
    if(implementations?.length===1&&types.has(implementations[0])) field.resolvedType=implementations[0];
    else if(iface) field.ambiguousRegistration=(implementations?.length||0)>1;
  }
  return {schemaVersion:1,types:[...types.values()].sort((a,b)=>a.id.localeCompare(b.id)),methods:methods.sort((a,b)=>a.id.localeCompare(b.id)||a.file.localeCompare(b.file)),methodLookup,registrations:resolvedRegistrations,diagnostics:{fallbackFiles,truncated}};
}
module.exports={buildDotnetProjectIndex};
