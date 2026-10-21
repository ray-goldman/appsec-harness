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
    { callerId:'A', calleeId:'B', argumentToCallerParameter:[0] },
    { callerId:'C', calleeId:'A', argumentToCallerParameter:[0] },
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
    {callerId:'C',calleeId:'A',argumentToCallerParameter:[0]},
    {callerId:'A',calleeId:'B',argumentToCallerParameter:[0]},
  ], { maxIterations:1 });
  assert.ok(result.iterations <= 1);
  assert.equal(result.truncated,true);
});
