'use strict';
// A closed source index for suppression proofs, separate from general taint
// coverage. Unsupported declarations or incomplete inputs never imply safety.
const {tokenizeCSharp}=require('./parsers/csharp/lexer');
const path=require('node:path').posix;
const name=t=>t?.kind==='identifier'?t.text.replace(/^@/,''):null;
const text=ts=>ts.map(t=>t.text).join('');
function split(ts,separator=','){
 const parts=[];let start=0,depth=0;
 for(let i=0;i<ts.length;i++){
  if(['(','[','{','<'].includes(ts[i].text))depth++;
  else if([')',']','}','>'].includes(ts[i].text))depth--;
  else if(!depth&&ts[i].text===separator){parts.push(ts.slice(start,i));start=i+1;}
 }parts.push(ts.slice(start));return parts;
}
function tokenFile(raw){
 const lex=tokenizeCSharp(raw),ts=lex.tokens,pairs=new Map(),stack=[];
 if(lex.errors.length||ts.length>20000||lex.regions.some(r=>r.kind==='directive'))return null;
 if(ts.some(t=>t.kind==='punctuation'&&/[\\\u0080-\uffff]/.test(t.text)))return null;
 for(let i=0;i<ts.length;i++){
  if(['(','[','{'].includes(ts[i].text))stack.push(i);
  else if([')',']','}'].includes(ts[i].text)){const open=stack.pop();if(open===undefined)return null;pairs.set(open,i);pairs.set(i,open);}
 }if(stack.length)return null;
 return{ts,pairs};
}
function parameters(ts){
 if(!ts.length)return[];
 const result=[];
 for(let p of split(ts)){
  if(p[0]?.text==='['&&p[2]?.text===']'&&['FromQuery','FromRoute','FromForm','FromHeader'].includes(name(p[1])))p=p.slice(3);
  if(p.length===4&&p[2].text==='='&&(['string','number','char'].includes(p[3].kind)||['true','false','null'].includes(p[3].text)))p=p.slice(0,2);
  if(p.length!==2||!name(p[0])||!name(p[1]))return null;
  result.push({type:name(p[0]),name:name(p[1])});
 }return result;
}
function buildProofIndex(sources,{complete=true,projects=[]}={}){
 if(!complete||projects.some(p=>!p.file.endsWith('.csproj'))||sources.length>1000||sources.reduce((n,s)=>n+Buffer.byteLength(s.raw),0)>8*1024*1024)return null;
 const files=[],types=[];let methodCount=0;
 for(const source of sources.filter(s=>/\.cs$/i.test(s.file))){
  if(source.raw.length>100000)return null;
  const lex=tokenFile(source.raw);if(!lex)return null;
  const {ts,pairs}=lex,imports=[];let namespace='',braceDepth=0;
  for(let i=0;i<ts.length;i++){
   if(ts[i].text==='{')braceDepth++;else if(ts[i].text==='}')braceDepth--;
   if(ts[i].text==='namespace'){
    let j=i+1;while(name(ts[j])||ts[j]?.text==='.')j++;
    if(namespace||ts[j]?.text!==';')return null;namespace=text(ts.slice(i+1,j));
   }
   if(!braceDepth&&ts[i].text==='using'&&name(ts[i+1])&&ts[i+1].text!=='var'){
    let j=i+1;while(name(ts[j])||ts[j]?.text==='.')j++;
    if(ts[j]?.text==='='||name(ts[i+1])==='static')return null;
    if(ts[j]?.text===';')imports.push(text(ts.slice(i+1,j)));
   }
  }
  const file={...source,...lex,imports,namespace,types:[]};files.push(file);
  for(let i=0;i<ts.length;i++){
   if(!['class','interface','record','struct'].includes(ts[i].text)||!name(ts[i+1]))continue;
   const type={name:name(ts[i+1]),kind:ts[i].text,namespace,file,methods:[],primary:[],start:ts[i].start};
   type.id=[namespace,type.name].filter(Boolean).join('.');
   let j=i+2;
   if(ts[j]?.text==='('){const end=pairs.get(j);if(end===undefined)return null;type.primary=parameters(ts.slice(j+1,end));j=end+1;}
   while(j<ts.length&&!['{',';'].includes(ts[j].text))j++;
   if(j===ts.length)return null;
   const header=text(ts.slice(i+2,j));
   type.header=header;type.open=j;type.close=ts[j].text==='{'?pairs.get(j):j;
   if(type.close===undefined)return null;
   // Generic/nested/partial types cannot contribute to this proof.
   type.unsupported=ts[i+2]?.text==='<'||ts.slice(Math.max(0,i-2),i).some(t=>t.text==='partial')||types.some(t=>t.file===file&&t.open<i&&t.close>i);
   file.types.push(type);types.push(type);
   if(type.kind==='interface'||type.close===j)continue;
   let segment=j+1;
   for(let k=j+1;k<type.close;k++){
    if(ts[k].text===';'){segment=k+1;continue;}
    if(ts[k].text==='{'&&pairs.has(k)){k=pairs.get(k);segment=k+1;continue;}
    if(ts[k].text!=='('||!name(ts[k-1]))continue;
    const close=pairs.get(k);if(close===undefined)return null;
    const prefix=ts.slice(segment,k-1),publicMethod=prefix.some(t=>t.text==='public');
    const after=ts[close+1]?.text;
    if(['{','=>'].includes(after)&&ts[k-2]?.text==='.')return null; // explicit interface dispatch is unsupported
    if(!['{','=>'].includes(after)||!prefix.some(t=>['public','private','protected','internal'].includes(t.text)))continue;
    if(prefix.some(t=>['=','=>'].includes(t.text)))continue;
    const params=parameters(ts.slice(k+1,close));
    let end=close+1,body;
    if(after==='{'){end=pairs.get(end);if(end===undefined)return null;body=ts.slice(close+2,end);}
    else{end=close+2;while(end<type.close&&ts[end].text!==';')end++;if(end>=type.close)return null;body=ts.slice(close+2,end);}
    const method={name:name(ts[k-1]),parameters:params,prefix,public:publicMethod,body,expression:after==='=>',start:ts[segment]?.start??ts[k-1].start,end:ts[end].end,owner:type,file};
    type.methods.push(method);methodCount++;if(methodCount>512)return null;
    k=end;segment=end+1;
   }
  }
 }
 // Interpolation is opaque in the lexer. Admit only simple numeric locals in
 // a flat method scope; all executable expressions and custom formatting decline.
 for(const file of files)for(const token of file.ts.filter(t=>t.kind==='interpolated-string')){
  if(!/^\$"(?:[^"\\{}]|\{[A-Za-z_]\w*\})*"$/.test(token.text))return null;
  const method=file.types.flatMap(t=>t.methods).find(m=>m.start<token.start&&m.end>token.end);
  if(!method)return null;
  const before=method.body.filter(t=>t.start<token.start);
  if(before.some(t=>['{','}'].includes(t.text)))return null;
  for(const hole of token.text.matchAll(/\{([A-Za-z_]\w*)\}/g)){
   if(!before.some((t,i)=>t.text==='var'&&name(before[i+1])===hole[1]&&text(before.slice(i+2,i+7))==='=int.Parse('))return null;
  }
 }
 const byId=new Map();
 for(const type of types){if(byId.has(type.id))type.unsupported=byId.get(type.id).unsupported=true;byId.set(type.id,type);}
 function resolve(typeName,file){
  const candidates=types.filter(t=>t.id===typeName||t.id===[file.namespace,typeName].filter(Boolean).join('.')||file.imports.some(ns=>t.id===ns+'.'+typeName));
  return candidates.length===1&&!candidates[0].unsupported?candidates[0]:null;
 }
 function framework(file,symbol,ns){
  if(types.some(t=>t.name===symbol||t.id===ns)||file.imports.some(x=>x!==ns&&!x.startsWith('System')&&!files.some(f=>f.namespace===x)))return false;
  return file.imports.includes(ns)||implicit(file);
 }
 function implicit(file){
  const owners=projects.filter(p=>file.file.startsWith(path.dirname(p.file)+'/'));
  owners.sort((a,b)=>b.file.length-a.file.length);const project=owners[0];
  if(!project||project.raw.length>=20000||!/<ImplicitUsings>enable<\/ImplicitUsings>/.test(project.raw))return false;
  let xml=project.raw.replace(/^\s*<Project Sdk="Microsoft\.NET\.Sdk(?:\.Web)?">/,'').replace(/<\/Project>\s*$/,'');
  xml=xml.replace(/<(TargetFramework|Nullable|ImplicitUsings|TreatWarningsAsErrors|RuntimeFrameworkVersion|RollForward)>[A-Za-z0-9_.-]+<\/\1>/g,'').replace(/<\/?(?:PropertyGroup|ItemGroup)>/g,'');
  xml=xml.replace(/<Compile Include="([A-Za-z0-9_./*-]+\.cs)"(?: Link="[A-Za-z0-9_./%()]+")?\s*\/>/g,(whole,include)=>{
   const resolved=path.normalize(path.join(path.dirname(project.file),include));
   if(resolved.startsWith('../')||path.isAbsolute(resolved)||resolved.includes('**'))return whole;
   const pattern=new RegExp('^'+resolved.split('*').map(p=>p.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')).join('[^/]*')+'$');
   return files.some(f=>pattern.test(f.file))?'':whole;
  });
  return !xml.trim();
 }
 return{files,types,resolve,framework,implicit};
}
module.exports={buildProofIndex,tokenFile,split,parameters,name,text};
