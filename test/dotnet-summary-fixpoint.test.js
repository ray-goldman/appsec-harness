'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { propagateSummaries } = require('../src/dotnet/summary-fixpoint');

test('propagates parameter-to-return over chains to a stable fixpoint', () => {
  const result = propagateSummaries([
    { methodId:'A', parameters:[{}], parameterToReturn:[], parameterToSinks:[] },
    { methodId:'B', parameters:[{}], parameterToReturn:[0], parameterToSinks:[] },
    { methodId:'C', parameters:[{}], parameterToReturn:[], parameterToSinks:[] },
  ], [
    { callerId:'A', calleeId:'B', argumentToCallerParameter:[0], returnsResult:true },
    { callerId:'C', calleeId:'A', argumentToCallerParameter:[0], returnsResult:true },
  ]);
  assert.deepEqual(result.summaries.find(x=>x.methodId==='A').parameterToReturn,[0]);
  assert.deepEqual(result.summaries.find(x=>x.methodId==='C').parameterToReturn,[0]);
  assert.equal(result.truncated,false);
});

test('reports iteration truncation and terminates recursive call graphs', () => {
  const result = propagateSummaries([
    {methodId:'A',parameters:[{}],parameterToReturn:[],parameterToSinks:[]},
    {methodId:'B',parameters:[{}],parameterToReturn:[0],parameterToSinks:[]},
    {methodId:'C',parameters:[{}],parameterToReturn:[],parameterToSinks:[]},
  ], [
    {callerId:'C',calleeId:'A',argumentToCallerParameter:[0],returnsResult:true},
    {callerId:'A',calleeId:'B',argumentToCallerParameter:[0],returnsResult:true},
  ], { maxIterations:1 });
  assert.ok(result.iterations <= 1);
  assert.equal(result.truncated,true);
});

test('discarding a helper result does not taint a constant return but still propagates sinks', () => {
  const result = propagateSummaries([
    {methodId:'A',parameters:[{}],parameterToReturn:[],parameterToSinks:[]},
    {methodId:'B',parameters:[{}],parameterToReturn:[0],parameterToSinks:[{parameter:0,category:'sql',sanitized:false}]},
  ], [{callerId:'A',calleeId:'B',argumentToCallerParameter:[0],returnsResult:false}]);
  assert.deepEqual(result.summaries[0].parameterToReturn, []);
  assert.equal(result.summaries[0].parameterToSinks.length, 1);
});

test('unknown targets and invalid argument mappings are unresolved, not proof', () => {
  const result = propagateSummaries([{methodId:'A',parameters:[{}],parameterToReturn:[0],parameterToSinks:[]}], [
    {callerId:'A',calleeId:'missing',argumentToCallerParameter:[0]},
    {callerId:'A',calleeId:'A',argumentToCallerParameter:[9],returnsResult:true},
  ]);
  assert.equal(result.unresolvedCalls, 2);
  assert.deepEqual(result.summaries[0].parameterToReturn, [0]);
});

test('bounded propagation is order-independent and validates its limits', () => {
  const summaries = ['A','B','C'].map(methodId=>({methodId,parameters:[{}],parameterToReturn:methodId==='C'?[0]:[],parameterToSinks:[]}));
  const calls = [
    {callerId:'A',calleeId:'B',argumentToCallerParameter:[0],returnsResult:true},
    {callerId:'B',calleeId:'C',argumentToCallerParameter:[0],returnsResult:true},
  ];
  assert.deepEqual(propagateSummaries(summaries,calls,{maxIterations:1}),propagateSummaries(summaries,[...calls].reverse(),{maxIterations:1}));
  for (const maxIterations of [0,-1,NaN,Infinity]) assert.throws(()=>propagateSummaries(summaries,calls,{maxIterations}),/limit/);
});

test('a propagated unsanitized sink invalidates an aggregate sanitizer claim', () => {
  const result=propagateSummaries([
    {methodId:'A',parameters:[{}],parameterToReturn:[],parameterToSinks:[{parameter:0,category:'xss',sanitized:true}],sanitizersBySink:{xss:true}},
    {methodId:'B',parameters:[{}],parameterToReturn:[],parameterToSinks:[{parameter:0,category:'xss',sanitized:false}]},
  ],[{callerId:'A',calleeId:'B',argumentToCallerParameter:[0]}]);
  assert.equal(result.summaries[0].sanitizersBySink.xss,false);
});
