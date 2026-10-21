'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { buildDotnetProjectIndex } = require('../src/dotnet/project-index');
const { resolveCall } = require('../src/dotnet/call-resolution');

test('equal-arity overloads remain ambiguous even with argument type hints', () => {
  const index = buildDotnetProjectIndex([{ file: 'A.cs', source: 'namespace N { class A { string Read(string x){return x;} int Read(int x){return x;} } }' }]);
  assert.equal(resolveCall({ name: 'Read', arity: 1, receiverType: 'N.A', argumentTypes: ['string'] }, index).status, 'ambiguous');
  assert.equal(resolveCall({ name: 'Read', arity: 1, receiverType: 'N.A' }, index).status, 'ambiguous');
});

test('requires an exact type identity and rejects malformed calls without throwing', () => {
  const index=buildDotnetProjectIndex([{file:'A.cs',source:'namespace N { class A { string Read(string x){return x;} } }'}]);
  assert.equal(resolveCall({name:'Read',arity:1,receiverType:'N.A',argumentTypes:['string']},index).status,'resolved');
  assert.equal(resolveCall({name:'Read',arity:1,receiverType:'A',argumentTypes:['string']},index).status,'unresolved');
  assert.equal(resolveCall(null,index).status,'unresolved');
  assert.equal(resolveCall({name:'Read',arity:1,receiverType:'N.A',argumentTypes:['string','int']},index).status,'unresolved');
});

test('callee optional and virtual declarations are unsupported even without caller flags', () => {
  for (const declaration of ['public virtual string Read(string x)', 'public string Read(string x = "default")', 'public string Read(params string[] x)']) {
    const index=buildDotnetProjectIndex([{file:'A.cs',source:'class A { '+declaration+' {return x;} }'}]);
    assert.equal(resolveCall({name:'Read',arity:1,receiverType:'A',argumentTypes:['string']},index).status,'unresolved');
  }
});

test('keeps unsupported call forms unresolved', () => {
  const index = buildDotnetProjectIndex([{ file: 'A.cs', source: 'class A { string Read(string x){return x;} }' }]);
  for (const call of [{ name:'Read', arity:1, receiverType:'A', namedArguments:true }, { name:'Read', arity:1, receiverType:'A', extension:true }, { name:'Read', arity:1, receiverType:'A', virtualDispatch:true }]) {
    assert.equal(resolveCall(call, index).status, 'unresolved');
  }
});
