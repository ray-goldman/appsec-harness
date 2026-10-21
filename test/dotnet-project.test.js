'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { buildDotnetProjectIndex, SUMMARY_SCHEMA } = require('../src/dotnet/project');

test('builds versioned summaries and only resolves unique name/arity call targets', () => {
  const files = [
    { file: 'Controller.cs', source: `class Controller { public string Get(string id) { return Service.Read(id); } }` },
    { file: 'Service.cs', source: `class Service { public string Read(string value) { return value; } }` },
  ];
  const project = buildDotnetProjectIndex(files);
  assert.equal(SUMMARY_SCHEMA, 'kayfabe-dotnet-method-summary@1');
  assert.equal(project.summaryVersion, 1);
  assert.ok(project.methods.some(m => m.name === 'Read' && m.summary.parameterToReturn.includes(0)));
  assert.ok(project.calls.some(call => call.name === 'Read' && call.resolved));
});

test('ambiguous equal-arity methods remain unresolved', () => {
  const project = buildDotnetProjectIndex([{ file: 'A.cs', source: `class A { string Read(string x){return x;} }` },
    { file: 'B.cs', source: `class B { string Read(string x){return x;} }` },
    { file: 'C.cs', source: `class C { string Go(){return Read("x");} }` }]);
  assert.ok(project.calls.filter(c => c.name === 'Read').every(c => !c.resolved));
  assert.ok(project.diagnostics.unresolvedCalls > 0);
});

test('private parameter summaries suppress only when visible callers all pass constants', () => {
  const project = buildDotnetProjectIndex([
    { file: 'A.cs', source: `class A { private string Read(string value) { return value; } public string Go() { return Read("fixed"); } }` },
  ]);
  const read = project.methods.find(m => m.name === 'Read');
  assert.deepEqual(read.summary.constantOnlySuppressedParameters, [0]);
});

test('sink matchers do not leak lastIndex between methods', () => {
  const project = buildDotnetProjectIndex([{ file: 'A.cs', source: `class A { public void One(string sql) { db.ExecuteSqlRaw(sql); } public void Two(string query) { db.ExecuteSqlRaw(query); } }` }]);
  assert.equal(project.methods.filter(m => m.summary.parameterToSink.some(s => s.category === 'sql')).length, 2);
});
