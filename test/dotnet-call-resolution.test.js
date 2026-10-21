'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { buildDotnetProjectIndex } = require('../src/dotnet/project-index');
const { resolveCall } = require('../src/dotnet/call-resolution');

test('resolves a unique member only when receiver type and argument types identify it', () => {
  const index = buildDotnetProjectIndex([{ file: 'A.cs', source: 'namespace N { class A { string Read(string x){return x;} int Read(int x){return x;} } }' }]);
  assert.equal(resolveCall({ name: 'Read', arity: 1, receiverType: 'N.A', argumentTypes: ['string'] }, index).status, 'resolved');
  assert.equal(resolveCall({ name: 'Read', arity: 1, receiverType: 'N.A' }, index).status, 'ambiguous');
});

test('keeps unsupported call forms unresolved', () => {
  const index = buildDotnetProjectIndex([{ file: 'A.cs', source: 'class A { string Read(string x){return x;} }' }]);
  for (const call of [{ name:'Read', arity:1, receiverType:'A', namedArguments:true }, { name:'Read', arity:1, receiverType:'A', extension:true }, { name:'Read', arity:1, receiverType:'A', virtualDispatch:true }]) {
    assert.equal(resolveCall(call, index).status, 'unresolved');
  }
});
