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
    {file:'Controller.cs',source:'namespace Demo { class Controller { public static void Get(string input){ Demo.Service.Run(input); } public static void Safe(string input){ Demo.Service.Run("fixed"); } } }'},
    {file:'Service.cs',source:'namespace Demo { class Service { public static void Run(string value){ Demo.Repository.Save(value); } } }'},
    {file:'Repository.cs',source:'namespace Demo { class Repository { public static void Save(string sql){ db.ExecuteSqlRaw(sql); } } }'},
  ];
  const result=analyzeDotnetSummaries(sources);
  assert.ok(result.summaries.find(s=>s.methodId.includes('.Get/')).parameterToSinks.some(s=>s.category==='sql'));
  assert.deepEqual(result.summaries.find(s=>s.methodId.includes('.Safe/')).parameterToSinks,[]);
  assert.equal(result.diagnostics.propagatedSinkMethods,2);
  assert.equal(result.diagnostics.findingsEnabled,false);
});

test('project summaries and route metrics are opt-in and do not create findings', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kayfabe-dotnet-project-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.writeFileSync(path.join(root, 'Program.cs'), `var group = app.MapGroup("/admin").RequireAuthorization();\ngroup.MapPost("/users", Update);\nclass UsersController : ControllerBase { [Authorize] [HttpPost("/save")] public IActionResult Save() { return Ok(); } }`);
  const basic = await scan(root, { includeTests: true });
  assert.equal(basic.stats.dotnetProject, null);
  const experimental = await scan(root, { includeTests: true, dotnetProjectAnalysis: true });
  assert.equal(experimental.stats.dotnetProject.summaryVersion, 1);
  assert.equal(experimental.stats.dotnetProject.findingsEnabled, false);
  assert.equal(experimental.stats.dotnetRoutes.routes, 2);
  assert.equal(experimental.stats.dotnetRoutes.authorized, 2);
  assert.deepEqual(experimental.findings.map(x => x.ruleId), basic.findings.map(x => x.ruleId));
});
