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
  assert.equal(resolveCall({name:'Read',arity:1,receiverType:'N.A',argumentTypes:['string'],instanceReceiver:true},index).status,'resolved');
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

test('resolves a single explicit DI implementation through an injected field', () => {
  const { analyzeDotnetSummaries }=require('../src/dotnet/analysis');
  const result=analyzeDotnetSummaries([
    {file:'Controller.cs',source:'namespace App { class Controller { private readonly IData _data; public Controller(IData data){ this._data=data; } public void Get(){ this._data.Save(Request.Query["q"].ToString()); } } }'},
    {file:'Data.cs',source:'namespace App { interface IData { void Save(string value); } class Data : IData { public void Save(string value){ db.ExecuteSqlRaw(value); } } }'},
    {file:'Program.cs',source:'namespace App { class Program { void Setup(){ services.AddScoped<IData, Data>(); } } }'},
  ]);
  assert.ok(result.findings.some(f=>f.category==='sql'&&f.callPath.length===2));
  assert.equal(result.calls.some(c=>c.reason==='multiple-compatible-targets'),false);
});

test('multiple DI implementations stay unresolved', () => {
  const { buildDotnetProjectIndex }=require('../src/dotnet/project-index');
  const { analyzeDotnetSummaries }=require('../src/dotnet/analysis');
  const files=[
    {file:'Controller.cs',source:'namespace App { class Controller { private readonly IData _data; public Controller(IData data){ this._data=data; } public void Get(){ this._data.Save(Request.Query["q"].ToString()); } } }'},
    {file:'Data.cs',source:'namespace App { interface IData { void Save(string value); } class Data : IData { public void Save(string value){ db.ExecuteSqlRaw(value); } } class OtherData : IData { public void Save(string value){ db.ExecuteSqlRaw(value); } } }'},
    {file:'Program.cs',source:'namespace App { class Program { void Setup(){ services.AddScoped<IData, Data>(); services.AddScoped<IData, OtherData>(); } } }'},
  ];
  const index=buildDotnetProjectIndex(files);
  assert.equal(index.registrations.get('App.IData').length,2);
  const result=analyzeDotnetSummaries(files);
  assert.equal(result.findings.some(f=>f.confidence==='high'),false);
  assert.ok(result.calls.some(c=>!c.resolved));
});

test('keeps unsupported call forms unresolved', () => {
  const index = buildDotnetProjectIndex([{ file: 'A.cs', source: 'class A { string Read(string x){return x;} }' }]);
  for (const call of [{ name:'Read', arity:1, receiverType:'A', namedArguments:true }, { name:'Read', arity:1, receiverType:'A', extension:true }, { name:'Read', arity:1, receiverType:'A', virtualDispatch:true }]) {
    assert.equal(resolveCall(call, index).status, 'unresolved');
  }
});

test('unique interface implementer resolves across namespaces without a registration', () => {
  const { analyzeDotnetSummaries } = require('../src/dotnet/analysis');
  const files = [
    {file:'Controller.cs',source:'class Controller { private readonly IData _data; public Controller(IData data) { _data = data; } public void Get(){ _data.Save(Request.Query["q"].ToString()); } }'},
    {file:'Data.cs',source:'namespace Storage { interface IData { void Save(string value); } class Data : IData { public void Save(string value) { db.ExecuteSqlRaw(value); } } }'},
  ];
  assert.ok(analyzeDotnetSummaries(files).findings.some(f=>f.confidence==='high'));
  files.push({file:'Other.cs',source:'namespace Storage { class Other : IData { public void Save(string value) { db.ExecuteSqlRaw(value); } } }'});
  assert.equal(analyzeDotnetSummaries(files).findings.some(f=>f.confidence==='high'),false);
});

test('a registration with an unresolved alternative cannot establish a unique implementation', () => {
  const { analyzeDotnetSummaries } = require('../src/dotnet/analysis');
  const files = [
    {file:'Controller.cs',source:'namespace App { class Controller { private readonly IData _data; public Controller(IData data){ _data=data; } public void Get(){ _data.Save(Request.Query["q"].ToString()); } } }'},
    {file:'Data.cs',source:'namespace App { interface IData { void Save(string value); } class Data : IData { public void Save(string value){ db.ExecuteSqlRaw(value); } } }'},
    {file:'Program.cs',source:'namespace App { class Program { void Setup(){ services.AddScoped<IData, Data>(); services.AddScoped<IData, Missing>(); } } }'},
  ];
  assert.equal(analyzeDotnetSummaries(files).findings.some(f=>f.confidence==='high'),false);
});
