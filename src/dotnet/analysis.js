'use strict';
const { buildDotnetProjectIndex }=require('./project-index');
const { summarizeMethod }=require('./method-summaries');
const { propagateSummaries }=require('./summary-fixpoint');
const { resolveCall }=require('./call-resolution');
const { tokenizeCSharp }=require('../parsers/csharp/lexer');

function analyzeDotnetSummaries(files, limits = {}) {
  const index=buildDotnetProjectIndex(files),calls=[];
  const methods=index.methods.filter(m=>!m.ambiguous&&!m.unsupported);
  const direct=methods.map(summarizeMethod),byId=new Map(methods.map(m=>[m.id,m])),directSummaryById=new Map(direct.map(s=>[s.methodId,s]));
  const typeIds=new Set(index.types.map(t=>t.id)),typeById=new Map(index.types.map(t=>[t.id,t])),typeIdsByShortName=new Map();
  for(const type of index.types) {
    const shortName=type.id.split('.').at(-1);
    if(!typeIdsByShortName.has(shortName)) typeIdsByShortName.set(shortName,[]);
    typeIdsByShortName.get(shortName).push(type.id);
  }
  const resolveType=(name,namespace)=>{
    if(typeIds.has(name))return name;
    const local=namespace?namespace+'.'+name:null;if(local&&typeIds.has(local))return local;
    const found=(typeIdsByShortName.get(name.split('.').at(-1))||[]).filter(id=>id.endsWith('.'+name)||id===name);
    return found.length===1?found[0].id:null;
  };
  let truncated=index.diagnostics.truncated;
  const requestSource=tokens=>{
    for(let i=0;i+2<tokens.length;i++) if(tokens[i].text==='Request'&&tokens[i+1].text==='.'&&['Query','Form','Headers','Cookies','QueryString'].includes(tokens[i+2].text)) return {source:'request',offset:tokens[i].start};
    return null;
  };
  for(const summary of direct) {
    if(summary.unresolvedCallSites.some(s=>['body-limit','token-limit','unsupported-control-flow','parameter-write'].includes(s.reason))) continue;
    const method=byId.get(summary.methodId),ts=tokenizeCSharp(method.body).tokens;
    const ret=ts.findIndex(t=>t.text==='return'),semi=ret<0?-1:ts.findIndex((t,i)=>i>ret&&t.text===';');
    const limit=semi<0?ts.length:semi;
    for(let i=0;i<limit;i++) {
      if(ts[i].text!=='('||ts[i-1]?.kind!=='identifier') continue;
      if(calls.length>=100000) {truncated=true;break;}
      let start=i-1;
      while(start>=2&&ts[start-1].text==='.'&&ts[start-2].kind==='identifier') start-=2;
      const name=ts[i-1].text.replace(/^@/,'');
      let receiverType=start===i-1?method.typeId:ts.slice(start,i-2).map(t=>t.text.replace(/^@/,'')).join('');
      let instanceReceiver=false;
      if(start!==i-1) {
        const receiverTokens=ts.slice(start,i-2),member=receiverTokens.at(-1)?.text.replace(/^@/,'');
        const owner=typeById.get(method.typeId);
        const field=owner?.fields.find(f=>f.name===member);
        const parameter=method.parameters.find(p=>p.name===member);
        const declared=field?.resolvedType||field?.type||parameter?.type;
        if(field?.ambiguousRegistration) receiverType='';
        else if(declared) {receiverType=resolveType(declared,method.namespace)||'';const implementations=index.registrations.get(receiverType);if(implementations?.length===1)receiverType=implementations[0];else if(implementations?.length>1)receiverType='';instanceReceiver=true;}
        else if(receiverTokens[0]?.text==='this') {receiverType=method.typeId;instanceReceiver=true;}
      }
      let depth=1,close=i+1,begin=i+1;const args=[];
      for(;close<ts.length;close++) {
        if(['(','['].includes(ts[close].text)) depth++;
        if([')',']'].includes(ts[close].text)) depth--;
        if(depth===0) {if(close>begin) args.push(ts.slice(begin,close));break;}
        if(depth===1&&ts[close].text===',') {args.push(ts.slice(begin,close));begin=close+1;}
      }
      const mapping=[],argumentTypes=[],sourceArguments=[];let unknown=close>=ts.length;
      for(let n=0;n<args.length;n++) {
        const arg=args[n],p=arg.length===1&&arg[0].kind==='identifier'?method.parameters.findIndex(x=>x.name===arg[0].text.replace(/^@/,'')):-1;
        if(p>=0) {mapping.push(p);argumentTypes.push(method.parameterTypes[p]);}
        else if(arg.length===1&&arg[0].kind==='string') {mapping.push(null);argumentTypes.push('string');}
        else if(arg.length===1&&arg[0].kind==='number'&&/^\d+$/.test(arg[0].text)) {mapping.push(null);argumentTypes.push('int');}
        else {
          const source=requestSource(arg);
          const toString=arg.some((token,j)=>token.text==='ToString'&&arg[j+1]?.text==='(');
          if(source&&toString) {mapping.push(null);argumentTypes.push('string');sourceArguments.push({argument:n,source:source.source,sourceLocation:{file:method.file,line:method.bodyLine+method.body.slice(0,source.offset).split(/\r?\n/).length-1}});}
          else {unknown=true;mapping.push(null);argumentTypes.push(null);}
        }
      }
      const resolved=unknown?{status:'unresolved',reason:'unsupported-argument',targets:[]}:resolveCall({name,receiverType,arity:args.length,argumentTypes,instanceReceiver},index);
      const target=byId.get(resolved.targets[0]),supported=resolved.status==='resolved';
      const callLine=method.bodyLine+method.body.slice(0,ts[i].start).split(/\r?\n/).length-1;
      calls.push({callerId:method.id,calleeId:supported?target.id:null,resolved:!!supported,reason:supported?null:resolved.reason||'unsupported-instance-call',
        name,arity:args.length,argumentToCallerParameter:mapping,sourceArguments,location:{file:method.file,line:callLine},
        returnsResult:ts[start-1]?.text==='return'&&ts[close+1]?.text===';'});
    }
  }
  const internalsVisibleTo=files.some(f=>/\bInternalsVisibleTo(?:Attribute)?\b/.test(f.source||f.raw||f.code||''));
  let constantSuppressedFlows=0;
  const incomingByTarget=new Map(),unresolvedNames=new Set();
  for(const call of calls) {
    if(call.calleeId) {
      if(!incomingByTarget.has(call.calleeId)) incomingByTarget.set(call.calleeId,[]);
      incomingByTarget.get(call.calleeId).push(call);
    } else if(call.name) unresolvedNames.add(call.name);
  }
  for(const method of methods.filter(m=>m.visibility==='private'||m.visibility==='internal'&&!internalsVisibleTo)) {
    const incoming=incomingByTarget.get(method.id)||[];
    const unresolvedByName=unresolvedNames.has(method.name);
    if(!incoming.length||unresolvedByName)continue;
    const summary=directSummaryById.get(method.id);
    const possiblyTainted=new Set();
    for(const call of incoming) {
      for(let i=0;i<method.parameters.length;i++) {
        if(call.argumentToCallerParameter[i]!==null||call.sourceArguments?.some(s=>s.argument===i)) possiblyTainted.add(i);
      }
    }
    for(let i=0;i<method.parameters.length;i++) {
      if(!possiblyTainted.has(i)) {
        const before=summary.parameterToSinks.length;
        summary.parameterToSinks=summary.parameterToSinks.filter(s=>s.parameter!==i);
        constantSuppressedFlows+=before-summary.parameterToSinks.length;
      }
    }
  }
  const result=propagateSummaries(direct,calls,limits),directById=new Map(direct.map(s=>[s.methodId,s]));
  const severity={sql:'high',command:'high',ssrf:'high',path:'high',xss:'medium'};
  const cwe={sql:[89],command:[78],ssrf:[918],path:[22],xss:[79]};
  const owasp={sql:'A05',command:'A05',ssrf:'A01',path:'A01',xss:'A05'};
  const flowFindings=new Map();
  for(const summary of result.summaries) for(const flow of summary.sourcesToSinks||[]) {
    if(flow.source!=='request'||!flow.sinkLocation?.file||!flow.sourceLocation?.file) continue;
    const key=[flow.sourceLocation.file,flow.sourceLocation.line,flow.sinkLocation.file,flow.sinkLocation.line,flow.category].join(':');
    if(!flowFindings.has(key)) flowFindings.set(key,{ruleId:'DOTNET-PROJECT-TAINT-'+flow.category.toUpperCase(),file:flow.sinkLocation.file,line:flow.sinkLocation.line,
      sourceLocation:flow.sourceLocation,callPath:flow.callPath,category:flow.category,severity:severity[flow.category]||'medium',confidence:'high',cwe:cwe[flow.category]||[],
      title:'Request data reaches a '+flow.category+' sink across project calls',detail:'Resolved path: '+flow.callPath.join(' → '),callPath:flow.callPath,taint:{source:flow.source,line:flow.sourceLocation.line},source:'sast',owasp:owasp[flow.category]||'A05'});
  }
  const highSinkLocations=new Set([...flowFindings.values()].map(f=>[f.file,f.line,f.ruleId].join(':')));
  const summariesById=new Map(result.summaries.map(s=>[s.methodId,s])),visibleCallTargets=new Set(calls.filter(c=>c.calleeId).map(c=>c.calleeId));
  for(const method of methods.filter(m=>['public','protected'].includes(m.visibility))) {
    const summary=summariesById.get(method.id);
    const hasVisibleCaller=visibleCallTargets.has(method.id);
    if(hasVisibleCaller) continue;
    for(const sink of summary.parameterToSinks) {
      const loc=sink.sinkLocation;if(!loc?.file)continue;
      const ruleId='DOTNET-PROJECT-TAINT-'+sink.category.toUpperCase(),key=[loc.file,loc.line,ruleId].join(':');
      if(highSinkLocations.has(key)||flowFindings.has(key))continue;
      flowFindings.set(key,{ruleId,file:loc.file,line:loc.line,category:sink.category,severity:severity[sink.category]||'medium',confidence:'low',cwe:cwe[sink.category]||[],
        title:'Public method parameter reaches a '+sink.category+' sink',detail:'No caller was visible in the analyzed project; verify external call sites and input validation.',
        callPath:sink.callPath||[method.id],taint:{source:'unresolved public parameter',line:method.startLine||1},source:'sast',owasp:owasp[sink.category]||'A05'});
    }
  }
  return {summaryVersion:1,summarySchema:'kayfabe-dotnet-method-summary@1',summaries:result.summaries,calls,findings:[...flowFindings.values()],
    diagnostics:{methods:index.methods.length,summarizedMethods:direct.length,unsupportedMethods:index.methods.length-direct.length,
      fallbackFiles:index.diagnostics.fallbackFiles,calls:calls.length,resolvedCalls:calls.filter(c=>c.resolved).length,unresolvedCalls:result.unresolvedCalls,
      iterations:result.iterations,truncated:truncated||result.truncated,maxIterations:limits.maxIterations||32,maxEdges:limits.maxEdges||100000,unresolvedSummarySites:direct.reduce((n,s)=>n+s.unresolvedCallSites.length,0),
      propagatedSinkMethods:result.summaries.filter(s=>s.parameterToSinks.length>directById.get(s.methodId).parameterToSinks.length).length,
      constantSuppressedFlows,flowFindings:flowFindings.size,findingsEnabled:true}};
}
module.exports={analyzeDotnetSummaries};
