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
