'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {scan}=require('../src/engine');
const db=`using Microsoft.EntityFrameworkCore;
namespace Demo.Data {
 public class CatalogDb : DbContext {
  public DbSet<Listing> Listings { get; set; }
 }
 public class Listing { public int Id { get; set; } public string Name { get; set; } }
}`;
const controller=body=>`using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Demo.Data;
namespace Demo.Web {
 public class CatalogController : Controller {
  private readonly CatalogDb _db;
  public CatalogController(CatalogDb db) { _db = db; }
  ${body}
 }
}`;
const action=body=>`public IActionResult Search(string q) {
 ${body}
}`;
const flow='string sql = $"SELECT * FROM Listings WHERE Name LIKE \'%{q}%\'";\n var rows = _db.Listings.FromSqlRaw(sql).ToList();\n return View(rows);';
async function findings(t,source,extra={}){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'kayfabe-mvc-sql-'));
 t.after(()=>{assert.equal(path.dirname(fs.realpathSync(root)),fs.realpathSync(os.tmpdir()));assert.ok(path.basename(root).startsWith('kayfabe-mvc-sql-'));fs.rmSync(root,{recursive:true,force:true});});
 for(const [name,text]of Object.entries({'Controller.cs':source,'Data.cs':db,...extra})){fs.mkdirSync(path.dirname(path.join(root,name)),{recursive:true});fs.writeFileSync(path.join(root,name),text);}
 return(await scan(root,{includeTests:true})).findings;
}
const hits=rows=>rows.filter(f=>f.ruleId==='CS-SQLI-002');
test('MVC string parameters flow through local SQL into typed EF raw SQL',async t=>{
 for(const body of [flow,'if (!IsAuthenticated()) return RedirectToAction("Login");\n'+flow,'if (string.IsNullOrEmpty(q)) return RedirectToAction("Index");\n'+flow,flow.replace('string sql =','var term = q;\n string sql =').replace('{q}','{term}'),flow.replace('$"SELECT * FROM Listings WHERE Name LIKE \'%{q}%\'"','"SELECT * FROM Listings WHERE Name = \'" + q + "\'"'),flow.replace('FromSqlRaw(sql)','FromSqlRaw(\n sql\n)'),flow.replace('return View(rows);','ViewBag.Query = q; return View(rows);')]){
  const got=hits(await findings(t,controller(action(body))));assert.equal(got.length,1,body);assert.equal(got[0].severity,'high');assert.equal(got[0].confidence,'high');assert.deepEqual(got[0].cwe,[89]);
 }
});
test('MVC SQL detection retains parameter binding and constant-query safe controls',async t=>{
 const variants=[
  flow.replace('.FromSqlRaw(sql)','.FromSqlInterpolated($"SELECT * FROM Listings WHERE Name = {q}")'),
  flow.replace('.FromSqlRaw(sql)','.FromSql($"SELECT * FROM Listings WHERE Name = {q}")'),
  flow.replace('var rows = _db.Listings.FromSqlRaw(sql)','var rows = _db.Listings.FromSqlRaw("SELECT * FROM Listings WHERE Name = {0}", q)'),
  flow.replace('$"SELECT * FROM Listings WHERE Name LIKE \'%{q}%\'"','"SELECT * FROM Listings"'),
  'q = "fixed";\n'+flow,
  flow.replace('var rows =','sql = "SELECT * FROM Listings";\n var rows ='),
  flow.replace('var rows =','sql = Normalize(sql);\n var rows ='),
  'if (true) return View();\n'+flow,
  'if (1 == 1) return View();\n'+flow,
  'if (string.Empty == "") return View();\n'+flow,
  'if (string.IsNullOrEmpty("")) return View();\n'+flow,
  'if (!Allowed.Contains(q)) return BadRequest();\n'+flow,
  'if (!IsSafeSort(q)) return BadRequest();\n'+flow,
  'if (q == "name") q = "Name"; else q = "Id";\n'+flow,
  flow.replace('string sql =','var n = int.Parse(q);\n string sql =').replace('{q}','{n}'),
 ];
 for(const body of variants)assert.equal(hits(await findings(t,controller(action(body)))).length,0,body);
});
test('MVC SQL source confidence requires action ownership and model-bound parameters',async t=>{
 for(const source of [
  controller(action(flow).replace('public IActionResult','private IActionResult')),
  controller(action(flow).replace('public IActionResult','public static IActionResult')),
  controller('[NonAction]\n'+action(flow)),
  controller('[Microsoft.AspNetCore.Mvc.NonActionAttribute]\n'+action(flow)),
  controller(action(flow).replace('string q','[FromServices] string q')),
  controller(action(flow)).replace(': Controller',': Formatter'),
  ...['public abstract','internal','public partial'].map(mod=>controller(action(flow)).replace('public class CatalogController',mod+' class CatalogController')),
  ...['[NonController]','[Microsoft.AspNetCore.Mvc.NonControllerAttribute]'].map(attr=>controller(action(flow)).replace('public class CatalogController',attr+' public class CatalogController')),
  controller(action(flow)).replace('public class CatalogController','public class CatalogController<T>'),
  controller(action(flow)).replace('using Microsoft.EntityFrameworkCore;',''),
  controller(action(flow)).replace('using Demo.Data;',''),
  controller(action(flow)).replace('public class CatalogController : Controller {','public class Outer { public class CatalogController : Controller {')+'}',
 ])assert.equal(hits(await findings(t,source)).length,0,source);
});
test('MVC SQL detects no flow from unrelated methods, shadowed fields or custom SQL APIs',async t=>{
 const cases=[
  [controller(action(flow)),{'Data.cs':db.replace(': DbContext',': Store')}],
  [controller(action(flow)),{'Data.cs':db.replace('public DbSet<Listing> Listings { get; set; }','public QueryClient Listings { get; set; }')}],
  [controller(action(flow)),{'Data.cs':db.replace('get; set;','get { return SafeQuery; }')}],
  ...['public class Controller {}','public class DbSet<T> {}','public class Wrapper { public object FromSqlRaw(string sql) { return null; } }','using DbContext = CustomDb;'].map(code=>[controller(action(flow)),{'Other.cs':code}]),
  [controller(action(flow)).replace('  public CatalogController(CatalogDb db) { _db = db; }',''),{}],
  [controller('[HttpGet]\n'+action(flow)),{'Other.cs':'public class HttpGetAttribute : System.Attribute {}'}],
  [controller(action('var _db = new SafeStore();\n'+flow)),{}],
  [controller(action(flow.replace('{q}','{input}'))+'\n public IActionResult Other(string input) { return View(input); }'),{}],
 ];
 for(const [source,extra]of cases)assert.equal(hits(await findings(t,source,extra)).length,0,source);
});
test('MVC SQL review regressions distinguish terminal sinks from unknown writes and expressions',async t=>{
 const terminal=flow.replace('var rows = _db.Listings.FromSqlRaw(sql).ToList();\n return View(rows);','return View(_db.Listings.FromSqlRaw(sql).ToList());');
 assert.equal(hits(await findings(t,controller(action(terminal)))).length,1);
 for(const before of ['(sql, q) = ("SELECT fixed", "fixed");','string discard = (sql = "SELECT fixed");'])
  assert.equal(hits(await findings(t,controller(action(flow.replace('var rows =',before+'\n var rows ='))))).length,0,before);
 for(const before of ['(_db, _) = (null, 1);','Use(_db = null);','(_db) = null;','this._db = null;','this._db.Listings = null;'])
  assert.equal(hits(await findings(t,controller(action(flow.replace('var rows =',before+'\n var rows ='))).replace('private readonly CatalogDb','private CatalogDb'))).length,0,before);
 for(const expression of ['false && _db.Listings.FromSqlRaw(sql).Any()','true ? false : _db.Listings.FromSqlRaw(sql).Any()','IsSafeQuery(sql) && _db.Listings.FromSqlRaw(sql).Any()'])
  assert.equal(hits(await findings(t,controller(action(flow.replace('var rows = _db.Listings.FromSqlRaw(sql).ToList();','var rows = '+expression+';'))))).length,0,expression);
});
test('MVC SQL source and sink checks ignore code strings and retain existing inline detections',async t=>{
 const inline=controller(action('var rows = _db.Listings.FromSqlRaw($"SELECT * FROM Listings WHERE Name = {q}").ToList(); return View(rows);'));
 assert.ok((await findings(t,inline)).some(f=>f.ruleId==='CS-SQLI-001'));
 assert.equal(hits(await findings(t,'/* '+controller(action(flow))+' */')).length,0);
 assert.equal(hits(await findings(t,'class Example { string sample = @"'+controller(action(flow)).replaceAll('"','""')+'"; }')).length,0);
 for(const body of [flow.replace('var rows =','return View();\n var rows ='),flow.replace('var rows =','throw new Exception();\n var rows ='),flow.replace('var rows =','Change(ref sql);\n var rows ='),flow.replace('var rows =','Func<string> change = () => sql = "SELECT fixed";\n change();\n var rows =')])
  assert.equal(hits(await findings(t,controller(action(body)))).length,0,body);
});
test('MVC SQL budgets and incomplete input decline only the additive rule',()=>{
 const {mvcSqlFindings}=require('../src/csharp-mvc-sql');
 const files=[{rel:'Controller.cs',lang:'csharp',code:controller(action(flow))},{rel:'Data.cs',lang:'csharp',code:db}];
 assert.equal(mvcSqlFindings({files}).length,1);
 assert.deepEqual(mvcSqlFindings({files,complete:false}),[]);
 assert.deepEqual(mvcSqlFindings({files:[{...files[0],code:controller(action(';'.repeat(4100)+flow))},files[1]]}),[]);
 for(const code of [files[0].code+' '.repeat(100001),files[0].code+';'.repeat(20001),files[0].code+'\nclass Unknown { int \uff51; }',files[0].code+'\npublic class Wrapper { public object FromSqlRaw'+' '.repeat(50000)+'(string s) { return null; } }'])
  assert.deepEqual(mvcSqlFindings({files:[{...files[0],code},files[1]]}),[]);
 assert.deepEqual(mvcSqlFindings({files:[...files,...Array.from({length:999},(_,i)=>({rel:`Extra${i}.cs`,lang:'csharp',code:'class Extra {}'}))]}),[]);
});
