'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { scan } = require('../src/engine');
const { analyzeDotnetSummaries } = require('../src/dotnet/analysis');

test('three-file static helper flow reaches the caller, while the constant twin does not', () => {
  const sources=[
    {file:'Controller.cs',source:'namespace Demo { class Controller { public static void Get(){ Demo.Service.Run(Request.Query["q"].ToString()); } public static void Safe(){ Demo.Service.Run("fixed"); } } }'},
    {file:'Service.cs',source:'namespace Demo { class Service { public static void Run(string value){ Demo.Repository.Save(value); } } }'},
    {file:'Repository.cs',source:'namespace Demo { class Repository { public static void Save(string sql){ db.ExecuteSqlRaw(sql); } } }'},
  ];
  const result=analyzeDotnetSummaries(sources);
  assert.ok(result.findings.some(f=>f.category==='sql'&&f.file==='Repository.cs'&&f.callPath.length===3));
  assert.deepEqual(result.summaries.find(s=>s.methodId.includes('.Safe/')).parameterToSinks,[]);
  assert.equal(result.diagnostics.propagatedSinkMethods,1);
  assert.equal(result.diagnostics.findingsEnabled,true);
  const bounded=analyzeDotnetSummaries(sources,{maxIterations:1,maxEdges:1});
  assert.equal(bounded.diagnostics.maxEdges,1);
  assert.equal(bounded.diagnostics.truncated,true);
});

test('public sink parameter without a visible caller is low confidence', () => {
  const result=analyzeDotnetSummaries([{file:'PublicApi.cs',source:'class PublicApi { public void Execute(string sql){ db.ExecuteSqlRaw(sql); } }'}]);
  assert.equal(result.findings.length,1);
  assert.equal(result.findings[0].confidence,'low');
});

test('request aliases reach a cross-file sink and reassigned constants do not', () => {
  const files = [
    {file:'Controller.cs',source:'class Controller { public static void Get(){ string value = Request.Query["q"].ToString(); Service.Run(value); } public static void Safe(){ string value = "fixed"; Service.Run(value); } }'},
    {file:'Service.cs',source:'class Service { public static void Run(string value){ string copy = value; Repository.Save(copy); } }'},
    {file:'Repository.cs',source:'class Repository { public static void Save(string value){ db.ExecuteSqlRaw(value); } }'},
  ];
  const result = analyzeDotnetSummaries(files);
  assert.ok(result.findings.some(f=>f.confidence==='high'&&f.sourceLocation?.file==='Controller.cs'&&f.callPath.length===3));
  assert.deepEqual(result.summaries.find(s=>s.methodId.includes('.Safe/')).sourcesToSinks,[]);
  const safe = analyzeDotnetSummaries(files.map(f=>f.file==='Controller.cs'?{...f,source:'class Controller { public static void Get(){ string value = Request.Query["q"].ToString(); value = "fixed"; Service.Run(value); } }'}:f));
  assert.equal(safe.findings.some(f=>f.confidence==='high'),false);
});

test('a public sink retains low-confidence external exposure despite constant visible callers', () => {
  const result = analyzeDotnetSummaries([{file:'Api.cs',source:'class Api { public static void Run(string value) { db.ExecuteSqlRaw(value); } public void Safe() { Run("fixed"); } }'}]);
  assert.ok(result.findings.some(f=>f.confidence==='low'&&f.category==='sql'));
});

test('an argument containing both a parameter and request source retains high source confidence', () => {
  const result = analyzeDotnetSummaries([{file:'C.cs',source:'class C { public void Get(string prefix) { C.Sink(prefix + Request.Query["q"].ToString()); } public static void Sink(string value) { db.ExecuteSqlRaw(value); } }'}]);
  assert.ok(result.findings.some(f=>f.confidence==='high'));
});

test('recursive calls with argument permutation still propagate request taint', () => {
  const result = analyzeDotnetSummaries([{file:'C.cs',source:'class C { public void Get() { C.A("fixed",Request.Query["q"].ToString()); } public static void A(string x,string y){db.ExecuteSqlRaw(x); C.B(y,x);} public static void B(string x,string y){C.A(x,y);} }'}]);
  assert.equal(result.diagnostics.truncated,false);
  assert.ok(result.findings.some(f=>f.confidence==='high'));
});

test('private helper sinks called only with constants are suppressed from transfer summaries', () => {
  const result=analyzeDotnetSummaries([
    {file:'Util.cs',source:'class Util { private static void Run(string sql){ db.ExecuteSqlRaw(sql); } public static void Safe(){ Run("fixed"); } }'},
  ]);
  assert.equal(result.diagnostics.constantSuppressedFlows,1);
  assert.equal(result.findings.length,0);
});

test('opt-in project finding reports the sink, source confidence and resolved call path', async t => {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'kayfabe-dotnet-taint-path-'));
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  fs.writeFileSync(path.join(root,'Controller.cs'),'namespace Demo { class Controller { public static void Get(){ Demo.Service.Run(Request.Query["q"].ToString()); } } }');
  fs.writeFileSync(path.join(root,'Service.cs'),'namespace Demo { class Service { public static void Run(string value){ Demo.Repository.Save(value); } } }');
  fs.writeFileSync(path.join(root,'Repository.cs'),'namespace Demo { class Repository { public static void Save(string sql){ db.ExecuteSqlRaw(sql); } } }');
  const baseline=await scan(root,{includeTests:true});
  assert.equal(baseline.findings.some(f=>f.ruleId.startsWith('DOTNET-PROJECT-TAINT-')),false);
  const result=await scan(root,{includeTests:true,dotnetProjectAnalysis:true});
  const finding=result.findings.find(f=>f.ruleId==='DOTNET-PROJECT-TAINT-SQL');
  assert.ok(finding);
  assert.equal(finding.confidence,'high');
  assert.equal(finding.file,'Repository.cs');
  assert.equal(finding.callPath.length,3);
  assert.equal(finding.summaryVersion,1);
  assert.equal(finding.sourceLocation.file,'Controller.cs');
  const {toSarif}=require('../src/report/sarif');
  const sarif=toSarif(result).runs[0].results.find(x=>x.ruleId===finding.ruleId);
  assert.equal(sarif.properties.summaryVersion,1);
  assert.deepEqual(sarif.properties.callPath,finding.callPath);
  assert.deepEqual(sarif.properties.sourceLocation,finding.sourceLocation);
});

test('project summaries and route metrics are opt-in and do not create findings', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kayfabe-dotnet-project-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.writeFileSync(path.join(root, 'Program.cs'), `var group = app.MapGroup("/admin").RequireAuthorization();\ngroup.MapPost("/users", Update);\nclass UsersController : ControllerBase { [Authorize] [HttpPost("/save")] public IActionResult Save() { return Ok(); } }`);
  const basic = await scan(root, { includeTests: true });
  assert.equal(basic.stats.dotnetProject, null);
  const experimental = await scan(root, { includeTests: true, dotnetProjectAnalysis: true });
  assert.equal(experimental.stats.dotnetProject.summaryVersion, 1);
  assert.equal(experimental.stats.dotnetProject.findingsEnabled, true);
  assert.equal(experimental.stats.dotnetRoutes.routes, 2);
  assert.equal(experimental.stats.dotnetRoutes.authorized, 2);
  assert.deepEqual(experimental.findings.map(x => x.ruleId), basic.findings.map(x => x.ruleId));
});
