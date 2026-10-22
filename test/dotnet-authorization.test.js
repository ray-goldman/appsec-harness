'use strict';
const { spawnSync } = require('node:child_process');
const test = require('node:test');
const assert = require('node:assert/strict');
const { buildDotnetRoutes, middlewareOrder } = require('../src/dotnet/authorization');

test('models MVC class/action authorization separately, with AllowAnonymous override', () => {
  const routes = buildDotnetRoutes([{ file: 'OrdersController.cs', source: `using Microsoft.AspNetCore.Mvc;\n[Authorize]\npublic class OrdersController : ControllerBase {\n [HttpPost("{id}")] public IActionResult Save(int id) { return Ok(); }\n [AllowAnonymous]\n [HttpGet] public IActionResult Public() { return Ok(); }\n}` }]);
  assert.equal(routes.length, 2);
  assert.equal(routes.find(x => x.action === 'Save').effectivePolicy, true);
  assert.equal(routes.find(x => x.action === 'Public').effectivePolicy, false);
});

test('models minimal API authorization and reports authentication middleware order', () => {
  const routes = buildDotnetRoutes([{ file: 'Program.cs', source: `var group = app.MapGroup("/admin").RequireAuthorization();\ngroup.MapPost("/users", Update);\napp.MapGet("/health", Health).AllowAnonymous();` }]);
  assert.equal(routes.find(x => x.path === '/admin/users').effectivePolicy, true);
  assert.equal(routes.find(x => x.path === '/health').effectivePolicy, false);
  assert.equal(middlewareOrder('app.UseAuthorization(); app.UseAuthentication();').status, 'misordered');
  assert.equal(middlewareOrder('// app.UseAuthorization();\napp.UseAuthentication();').status, 'not-visible');
});
test('route extraction terminates on large masked comments before a controller declaration', () => {
  const script = `const {buildDotnetRoutes}=require('./src/dotnet/authorization'); const routes=buildDotnetRoutes([{file:'Controller.cs',source:'/*'+' '.repeat(100000)+'*/ class TestController {}'}]); if(routes.length) process.exit(1);`;
  const result = spawnSync(process.execPath, ['-e', script], {cwd:require('node:path').resolve(__dirname,'..'), timeout:2000});
  assert.equal(result.error,undefined, String(result.error));
  assert.equal(result.status,0);
});
