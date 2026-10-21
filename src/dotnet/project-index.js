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
    if(tokens[open]?.text==='{'&&pairs.has(open)) types.push({name:tokens[i+1].text.replace(/^@/,''),start:tokens[i].start,bodyStart:tokens[open].start,bodyEnd:tokens[pairs.get(open)].end,partial:prefix(i).includes('partial'),unsupported:tokens[i+2]?.text==='<'});
  }
  return ast.methods.map(method=>{
    const owners=types.filter(t=>method.start>=t.bodyStart&&method.end<=t.bodyEnd).sort((a,b)=>a.start-b.start);
    const owner=owners.at(-1);
    const ns=namespaces.filter(n=>method.start>=n.start&&method.end<=n.end).sort((a,b)=>a.start-b.start).map(n=>n.name).join('.');
    const nameIndex=tokens.findIndex(t=>t.start===method.start);
    const modifiers=prefix(nameIndex);
    const header=tokens.filter(t=>t.start>=method.start&&t.start<method.bodyStart);
    const unsupported=owners.some(o=>o.unsupported)||modifiers.some(t=>['virtual','override','abstract'].includes(t))||header.some(t=>['=',':','params','this','ref','out','in','[','<'].includes(t.text))||owner?.name===method.name||
      ast.methods.some(other=>other!==method&&other.bodyStart<method.start&&other.bodyEnd>=method.end);
    return {...method,namespace:ns,typeName:owners.map(t=>t.name).join('.'),ownerResolved:!!owner,ownerStart:owner?.start,partial:owner?.partial,unsupported,
      visibility:['public','protected','internal','private'].find(v=>modifiers.includes(v))||'private',static:modifiers.includes('static'),
      body:source.slice(method.bodyStart+1,method.bodyEnd-1)};
  });
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
    for(const m of findOwners(source,ast,tokens)) {
      if(!m.ownerResolved) continue;
      if(methods.length>=50000) {truncated=true;break;}
      const typeId=[m.namespace,m.typeName].filter(Boolean).join('.');
      if(!types.has(typeId)) types.set(typeId,{id:typeId,namespace:m.namespace,name:m.typeName,declarations:new Map()});
      const type=types.get(typeId);
      type.declarations.set(file+':'+m.ownerStart,{file,start:m.ownerStart,partial:m.partial});
      const signature=m.parameters.map(p=>(p.type||'?').replace(/\s+/g,'')).join(',');
      methods.push({id:typeId+'.'+m.name+'/'+m.parameters.length+'('+signature+')',file,namespace:m.namespace,typeId,name:m.name,arity:m.parameters.length,parameterTypes:m.parameters.map(p=>p.type),parameters:m.parameters,visibility:m.visibility,static:m.static,unsupported:m.unsupported,start:m.start,end:m.end,bodyStart:m.bodyStart,bodyEnd:m.bodyEnd,body:m.body});
    }
  }
  const counts=new Map();
  for(const method of methods) counts.set(method.id,(counts.get(method.id)||0)+1);
  for(const type of types.values()) {
    type.declarations=[...type.declarations.values()];
    type.files=[...new Set(type.declarations.map(d=>d.file))].sort();
    type.partial=type.declarations.every(d=>d.partial);
    type.ambiguous=type.declarations.length>1&&!type.partial;
  }
  for(const method of methods) method.ambiguous=counts.get(method.id)>1||types.get(method.typeId).ambiguous;
  const methodLookup=new Map();
  for(const method of methods) {
    const key=JSON.stringify([method.typeId,method.name,method.arity]);
    if(!methodLookup.has(key)) methodLookup.set(key,[]);
    methodLookup.get(key).push(method);
  }
  return {schemaVersion:1,types:[...types.values()].sort((a,b)=>a.id.localeCompare(b.id)),methods:methods.sort((a,b)=>a.id.localeCompare(b.id)||a.file.localeCompare(b.file)),methodLookup,diagnostics:{fallbackFiles,truncated}};
}
module.exports={buildDotnetProjectIndex};
