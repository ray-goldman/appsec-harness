'use strict';

function propagateSummaries(inputSummaries,calls,{maxIterations=32,maxEdges=100000}={}) {
  for(const [name,value,cap] of [['maxIterations',maxIterations,256],['maxEdges',maxEdges,100000]]) {
    if(!Number.isInteger(value)||value<1||value>cap) throw new RangeError('invalid '+name+' limit');
  }
  const clone=s=>({...s,parameterToReturn:[...new Set(s.parameterToReturn||[])].sort((a,b)=>a-b),parameterToSinks:(s.parameterToSinks||[]).map(x=>({...x})),sourcesToSinks:(s.sourcesToSinks||[]).map(x=>({...x,sourceLocation:{...x.sourceLocation},sinkLocation:{...x.sinkLocation},callPath:[...x.callPath]}))});
  let summaries=inputSummaries.slice(0,50000).map(clone).sort((a,b)=>a.methodId.localeCompare(b.methodId));
  const byId=new Map(summaries.map(s=>[s.methodId,s]));
  if(byId.size!==summaries.length) throw new Error('duplicate method summary identity');
  const valid=call=>{
    const caller=byId.get(call?.callerId),callee=byId.get(call?.calleeId),mapping=call?.argumentToCallerParameter;
    return caller && callee && call.resolved!==false && Array.isArray(mapping) && mapping.length===callee.parameters.length && mapping.every(p=>p===null||Number.isInteger(p)&&p>=0&&p<caller.parameters.length);
  };
  const unresolvedCalls=calls.filter(c=>!valid(c)).length;
  const edges=calls.filter(valid)
    .map(call=>({call,key:JSON.stringify([call.callerId,call.calleeId,call.name,call.arity,call.argumentToCallerParameter,call.sourceArguments,call.location,call.returnsResult])}))
    .sort((a,b)=>a.key.localeCompare(b.key)).slice(0,maxEdges).map(item=>item.call);
  let iterations=0,changed=false;
  const truncated=calls.filter(valid).length>maxEdges||inputSummaries.length>50000;
  const sinkKey = sink => JSON.stringify([sink.parameter,sink.category,sink.sanitized,sink.sinkLocation||null]);
  const flowKey = flow => JSON.stringify([flow.source,flow.category,flow.sourceLocation,flow.sinkLocation]);
  do {
    const previous=new Map(summaries.map(s=>[s.methodId,s]));
    summaries=summaries.map(clone);
    const next=new Map(summaries.map(s=>[s.methodId,s]));
    changed=false;iterations++;
    for(const call of edges) {
      const caller=next.get(call.callerId),callee=previous.get(call.calleeId);
      const sinkKeys=new Set(caller.parameterToSinks.map(sinkKey)),flowKeys=new Set(caller.sourcesToSinks.map(flowKey));
      for(const input of call.sourceArguments||[]) {
        for(const sink of callee.parameterToSinks.filter(s=>s.parameter===input.argument&&!s.sanitized)) {
          const flow={source:input.source,category:sink.category,sourceLocation:input.sourceLocation,sinkLocation:sink.sinkLocation||call.location,callPath:[call.callerId,...(sink.callPath||[call.calleeId])]};
          const key=flowKey(flow);
          if(!flowKeys.has(key)) {flowKeys.add(key);caller.sourcesToSinks.push(flow);changed=true;}
        }
      }
      for(const flow of callee.sourcesToSinks||[]) {
        const wrapped={...flow,callPath:[call.callerId,...flow.callPath]};
        const key=flowKey(wrapped);
        if(!flowKeys.has(key)) {flowKeys.add(key);caller.sourcesToSinks.push(wrapped);changed=true;}
      }
      if(call.returnsResult===true) for(const parameter of callee.parameterToReturn) {
        const p=call.argumentToCallerParameter[parameter];
        if(Number.isInteger(p)&&!caller.parameterToReturn.includes(p)) {caller.parameterToReturn.push(p);changed=true;}
      }
      for(const sink of callee.parameterToSinks) {
        const p=call.argumentToCallerParameter[sink.parameter];
        if(!Number.isInteger(p)) continue;
        const callPath=[call.callerId,...(sink.callPath||[call.calleeId])];
        const key=sinkKey({...sink,parameter:p});
        if(!sinkKeys.has(key)) {
          sinkKeys.add(key);
          caller.parameterToSinks.push({...sink,parameter:p,callPath});changed=true;
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
