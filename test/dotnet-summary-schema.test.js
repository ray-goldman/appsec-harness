'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { SUMMARY_SCHEMA_VERSION, createMethodSummary, serializeMethodSummary, deserializeMethodSummary } = require('../src/dotnet/summary-schema');
const { buildDotnetProjectIndex } = require('../src/dotnet/project-index');

test('summary schema is versioned and rejects incompatible versions', () => {
  assert.equal(SUMMARY_SCHEMA_VERSION, 1);
  const summary = createMethodSummary({ methodId: 'N.C.M/1' });
  assert.equal(deserializeMethodSummary(serializeMethodSummary(summary)).methodId, 'N.C.M/1');
  assert.throws(() => deserializeMethodSummary(JSON.stringify({ ...summary, schemaVersion: 2 })), /unsupported summary schema/);
});

test('serialized summaries reject malformed collections and out-of-range flow indices', () => {
  const valid=createMethodSummary({methodId:'A',parameters:[{name:'value'}]});
  for (const patch of [{parameterToReturn:[4]},{parameterToSinks:[{parameter:-1,category:'sql',sanitized:false}]},{unresolvedCallSites:'none'},{sanitizersBySink:{sql:'yes'}}]) {
    assert.throws(()=>deserializeMethodSummary(JSON.stringify({...valid,...patch})),/invalid method summary/);
  }
});

test('namespace and nested-type ownership comes from code tokens, not literal text', () => {
  const index=buildDotnetProjectIndex([{file:'A.cs',source:'// namespace Fake;\nnamespace Outer { namespace Inner { class Parent { class Child { string Read(){return "namespace Decoy;";} } } } }'}]);
  assert.equal(index.methods[0].id,'Outer.Inner.Parent.Child.Read/0()');
  const fileScoped=buildDotnetProjectIndex([{file:'A.cs',source:'namespace Real; class C { string Read(){return "x";} }'}]);
  assert.equal(fileScoped.methods[0].id,'Real.C.Read/0()');
});

test('two non-partial declarations are ambiguous, not a partial type', () => {
  const index=buildDotnetProjectIndex(['A','B'].map(name=>({file:name+'.cs',source:'class C { string Read(){return "x";} }'})));
  assert.equal(index.types[0].partial,false);
  assert.ok(index.methods.every(m=>m.ambiguous));
});

test('partial declarations share a type identity while method overloads remain distinct', () => {
  const index = buildDotnetProjectIndex([
    { file: 'A.cs', source: 'namespace N { partial class C { public string Read(string x) { return x; } } }' },
    { file: 'B.cs', source: 'namespace N { partial class C { public string Read(int x) { return "x"; } } }' },
  ]);
  assert.deepEqual(index.methods.map(m => m.id).sort(), ['N.C.Read/1(int)', 'N.C.Read/1(string)']);
  assert.ok(index.types.find(t => t.id === 'N.C').partial);
});

test('same named types in different namespaces have distinct identities', () => {
  const index = buildDotnetProjectIndex([
    { file: 'A.cs', source: 'namespace A { class C { string Read() { return "a"; } } }' },
    { file: 'B.cs', source: 'namespace B { class C { string Read() { return "b"; } } }' },
  ]);
  assert.deepEqual(index.methods.map(m => m.id).sort(), ['A.C.Read/0()', 'B.C.Read/0()']);
});
