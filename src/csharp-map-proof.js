'use strict';
const {buildProofIndex,name,text,split}=require('./csharp-proof-index');
// Only a fresh local map, literal entries, one terminating lookup and one
// selected-value command assignment. Any alias/extra use/write declines it.
function createCSharpMapProof(sources,options={}){
 const index=buildProofIndex(sources,options),proved=new Map();if(!index)return()=>false;
 for(const file of index.files){
  if(!index.implicit(file)||!index.framework(file,'Dictionary','System.Collections.Generic'))continue;
  for(const owner of file.types)for(const method of owner.methods){
   if(owner.unsupported||!method.parameters||method.body.length>4096||method.body.some(t=>t.kind==='interpolated-string'))continue;
   const ts=method.body;
   for(let i=0;i+12<ts.length;i++){
    if(ts[i].text!=='var'||!name(ts[i+1])||text(ts.slice(i+2,i+10))!=='=newDictionary<string,string>')continue;
    const map=name(ts[i+1]);let open=i+10;
    if(ts[open]?.text==='('){let j=open+1;while(j<ts.length&&ts[j].text!==')')j++;if(!['','StringComparer.Ordinal','StringComparer.OrdinalIgnoreCase'].includes(text(ts.slice(open+1,j))))continue;open=j+1;}
    if(ts[open]?.text!=='{')continue;
    let close=open+1;while(close<ts.length&&ts[close].text!=='}')close++;
    if(ts[close+1]?.text!==';')continue;
    const entries=split(ts.slice(open+1,close));
    if(!entries.length||entries.length>64||!entries.every(p=>p.length===5&&p[0].text==='['&&p[1].kind==='string'&&p[2].text===']'&&p[3].text==='='&&p[4].kind==='string'))continue;
    const keys=entries.map(p=>p[1].text);if(new Set(keys).size!==keys.length)continue;
    const uses=ts.map((t,k)=>name(t)===map?k:-1).filter(k=>k>=0);
    if(uses.length!==2||uses[0]!==i+1)continue;
    const call=uses[1],begin=call-3;
    if(text(ts.slice(begin,call))!=='if(!'||text(ts.slice(call,call+4))!==map+'.TryGetValue(')continue;
    let end=call+4,depth=1;for(;end<ts.length;end++){if(ts[end].text==='(')depth++;if(ts[end].text===')'&&!--depth)break;}
    const args=split(ts.slice(call+4,end));if(args.length!==2||text(args[1].slice(0,2))!=='outvar'||args[1].length!==3||!name(args[1][2])||ts[end+1]?.text!==')')continue;
    const selected=name(args[1][2]);let tail=end+2;
    if(ts[tail]?.text!=='throw')continue;
    while(tail<ts.length&&ts[tail].text!==';')tail++;
    const selectedUses=ts.map((t,k)=>name(t)===selected?k:-1).filter(k=>k>=0);
    if(selectedUses.length!==2)continue;
    const value=selectedUses[1];
    if(value<=tail||ts[value-1]?.text!=='+'||ts[value-2]?.kind!=='string'||ts[value-3]?.text!=='='||ts[value-4]?.text!=='Arguments'||ts[value-5]?.text!=='.'||ts[value+1]?.text!==';')continue;
    // Nothing conditional, deferred or nested may surround declaration/guard/sink.
    if(ts.slice(0,i).some(t=>['{','}','if','for','while','try','=>'].includes(t.text))||ts.slice(close+2,begin).length||ts.slice(tail+1,value-5).some(t=>['if','else','for','while','try','{','}','=>','ref','out'].includes(t.text)))continue;
    const line=file.raw.slice(0,ts[value-4].start).split(/\r?\n/).length;
    const rawLine=file.raw.split(/\r?\n/)[line-1];
    if((rawLine.match(/\.Arguments\s*=|\bProcess\.Start\s*\(/g)||[]).length!==1)continue;
    if(!proved.has(file.file))proved.set(file.file,new Set());proved.get(file.file).add(line);
   }
  }
 }
 return(file,line)=>proved.get(file)?.has(line)||false;
}
module.exports={createCSharpMapProof};
