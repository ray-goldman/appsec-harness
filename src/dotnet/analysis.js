'use strict';
const { buildDotnetProjectIndex } = require('./project-index');
const { summarizeMethod } = require('./method-summaries');
const { propagateSummaries } = require('./summary-fixpoint');
const { resolveCall } = require('./call-resolution');
const { tokenizeCSharp } = require('../parsers/csharp/lexer');

// Diagnostic-only integration. The supported edges are direct static calls
// passing parameters or literals. No DI, alias, control-flow, or caller-source
// inference is implied by these counts.
function analyzeDotnetSummaries(files) {
  const index=buildDotnetProjectIndex(files), calls=[];
  const methods=index.methods.filter(m=>!m.ambiguous&&!m.unsupported);
  const direct=methods.map(summarizeMethod);
  const byId=new Map(methods.map(m=>[m.id,m]));
  let truncated=index.diagnostics.truncated;
  for(const summary of direct) {
    if(summary.unresolvedCallSites.some(s=>['body-limit','token-limit','unsupported-control-flow','parameter-write'].includes(s.reason))) continue;
    const method=byId.get(summary.methodId),ts=tokenizeCSharp(method.body).tokens;
    const ret=ts.findIndex(t=>t.text==='return');
    const semi=ret<0?-1:ts.findIndex((t,i)=>i>ret&&t.text===';');
    const limit=semi<0?ts.length:semi;
    for(let i=0;i<limit;i++) {
      if(ts[i].text!=='('||ts[i-1]?.kind!=='identifier') continue;
      if(calls.length>=100000) {truncated=true;break;}
      let start=i-1;
      while(start>=2&&ts[start-1].text==='.'&&ts[start-2].kind==='identifier') start-=2;
      const name=ts[i-1].text.replace(/^@/,''),receiverType=start===i-1?method.typeId:ts.slice(start,i-2).map(t=>t.text.replace(/^@/,'')).join('');
      let depth=1,close=i+1,begin=i+1;const args=[];
      for(;close<ts.length;close++) {
        if(['(','['].includes(ts[close].text)) depth++;
        if([')',']'].includes(ts[close].text)) depth--;
        if(depth===0) {if(close>begin) args.push(ts.slice(begin,close));break;}
        if(depth===1&&ts[close].text===',') {args.push(ts.slice(begin,close));begin=close+1;}
      }
      const mapping=[],argumentTypes=[];let unknown=close>=ts.length;
      for(const arg of args) {
        const p=arg.length===1&&arg[0].kind==='identifier'?method.parameters.findIndex(x=>x.name===arg[0].text.replace(/^@/,'')):-1;
        if(p>=0) {mapping.push(p);argumentTypes.push(method.parameterTypes[p]);}
        else if(arg.length===1&&arg[0].kind==='string') {mapping.push(null);argumentTypes.push('string');}
        else if(arg.length===1&&arg[0].kind==='number'&&/^\d+$/.test(arg[0].text)) {mapping.push(null);argumentTypes.push('int');}
        else {unknown=true;mapping.push(null);argumentTypes.push(null);}
      }
      const resolved=unknown?{status:'unresolved',reason:'unsupported-argument',targets:[]}:resolveCall({name,receiverType,arity:args.length,argumentTypes},index);
      const target=byId.get(resolved.targets[0]);
      const supported=resolved.status==='resolved'&&target?.static;
      calls.push({callerId:method.id,calleeId:supported?target.id:null,resolved:!!supported,reason:supported?null:resolved.reason||'unsupported-instance-call',argumentToCallerParameter:mapping,returnsResult:ts[start-1]?.text==='return'&&ts[close+1]?.text===';'});
    }
  }
  const result=propagateSummaries(direct,calls);
  const directById=new Map(direct.map(s=>[s.methodId,s]));
  return {summaryVersion:1,summarySchema:'kayfabe-dotnet-method-summary@1',summaries:result.summaries,calls,
    diagnostics:{methods:index.methods.length,summarizedMethods:direct.length,unsupportedMethods:index.methods.length-direct.length,
      fallbackFiles:index.diagnostics.fallbackFiles,calls:calls.length,resolvedCalls:calls.filter(c=>c.resolved).length,
      unresolvedCalls:result.unresolvedCalls,iterations:result.iterations,truncated:truncated||result.truncated,
      unresolvedSummarySites:direct.reduce((n,s)=>n+s.unresolvedCallSites.length,0),
      propagatedSinkMethods:result.summaries.filter(s=>s.parameterToSinks.length>directById.get(s.methodId).parameterToSinks.length).length,
      findingsEnabled:false}};
}
module.exports={analyzeDotnetSummaries};
