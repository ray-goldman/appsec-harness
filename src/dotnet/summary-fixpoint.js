'use strict';

function propagateSummaries(inputSummaries, calls, { maxIterations = 32, maxEdges = 100000 } = {}) {
  const summaries = inputSummaries.slice(0, 50000).map(summary => ({ ...summary,
    parameterToReturn: [...new Set(summary.parameterToReturn || [])].sort((a,b)=>a-b),
    parameterToSinks: [...(summary.parameterToSinks || [])] }));
  const byId = new Map(summaries.map(summary => [summary.methodId, summary]));
  const edges = calls.slice(0, maxEdges);
  let iterations = 0, changed = false, truncated = calls.length > maxEdges || inputSummaries.length > 50000;
  do {
    changed = false; iterations++;
    for (const call of edges) {
      const caller = byId.get(call.callerId), callee = byId.get(call.calleeId);
      if (!caller || !callee || !Array.isArray(call.argumentToCallerParameter)) continue;
      for (const calleeIndex of callee.parameterToReturn) {
        const callerIndex = call.argumentToCallerParameter[calleeIndex];
        if (Number.isInteger(callerIndex) && !caller.parameterToReturn.includes(callerIndex)) {
          caller.parameterToReturn.push(callerIndex); caller.parameterToReturn.sort((a,b)=>a-b); changed = true;
        }
      }
      for (const sink of callee.parameterToSinks) {
        const callerIndex = call.argumentToCallerParameter[sink.parameter];
        if (!Number.isInteger(callerIndex)) continue;
        if (!caller.parameterToSinks.some(item => item.parameter === callerIndex && item.category === sink.category && item.sanitized === sink.sanitized)) {
          caller.parameterToSinks.push({ ...sink, parameter: callerIndex }); changed = true;
        }
      }
    }
    if (changed && iterations >= maxIterations) { truncated = true; break; }
  } while (changed);
  return { summaries, iterations, truncated, unresolvedCalls: calls.filter(call => !call.callerId || !call.calleeId).length };
}

module.exports = { propagateSummaries };
