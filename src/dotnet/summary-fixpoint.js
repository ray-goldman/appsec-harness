'use strict';

function propagateSummaries(inputSummaries,calls,{maxIterations=32,maxEdges=100000}={}) {
  for(const [name,value,cap] of [['maxIterations',maxIterations,256],['maxEdges',maxEdges,100000]]) {
    if(!Number.isInteger(value)||value<1||value>cap) throw new RangeError('invalid '+name+' limit');
  }
  const clone=s=>({...s,parameterToReturn:[...new Set(s.parameterToReturn||[])].sort((a,b)=>a-b),parameterToSinks:(s.parameterToSinks||[]).map(x=>({...x}))});
  let summaries=inputSummaries.slice(0,50000).map(clone).sort((a,b)=>a.methodId.localeCompare(b.methodId));
  const byId=new Map(summaries.map(s=>[s.methodId,s]));
  if(byId.size!==summaries.length) throw new Error('duplicate method summary identity');
  const valid=call=>{
    const caller=byId.get(call?.callerId),callee=byId.get(call?.calleeId),mapping=call?.argumentToCallerParameter;
    return caller && callee && call.resolved!==false && Array.isArray(mapping) && mapping.length===callee.parameters.length && mapping.every(p=>p===null||Number.isInteger(p)&&p>=0&&p<caller.parameters.length);
  };
  const unresolvedCalls=calls.filter(c=>!valid(c)).length;
  const edges=calls.filter(valid).sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b))).slice(0,maxEdges);
  let iterations=0,changed=false;
  const truncated=calls.filter(valid).length>maxEdges||inputSummaries.length>50000;
  do {
    const previous=new Map(summaries.map(s=>[s.methodId,s]));
    summaries=summaries.map(clone);
    const next=new Map(summaries.map(s=>[s.methodId,s]));
    changed=false;iterations++;
    for(const call of edges) {
      const caller=next.get(call.callerId),callee=previous.get(call.calleeId);
      if(call.returnsResult===true) for(const parameter of callee.parameterToReturn) {
        const p=call.argumentToCallerParameter[parameter];
        if(Number.isInteger(p)&&!caller.parameterToReturn.includes(p)) {caller.parameterToReturn.push(p);changed=true;}
      }
      for(const sink of callee.parameterToSinks) {
        const p=call.argumentToCallerParameter[sink.parameter];
        if(!Number.isInteger(p)) continue;
        if(!caller.parameterToSinks.some(s=>s.parameter===p&&s.category===sink.category&&s.sanitized===sink.sanitized)) {
          caller.parameterToSinks.push({...sink,parameter:p});changed=true;
        }
      }
    }
    for(const summary of summaries) {
      summary.parameterToReturn.sort((a,b)=>a-b);
      summary.parameterToSinks.sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b)));
      summary.sanitizersBySink=Object.fromEntries([...new Set(summary.parameterToSinks.map(s=>s.category))].map(category=>[category,summary.parameterToSinks.filter(s=>s.category===category).every(s=>s.sanitized===true)]));
    }
  } while(changed && iterations<maxIterations);
  return {summaries,iterations,truncated:truncated||changed,unresolvedCalls};
}
module.exports={propagateSummaries};
