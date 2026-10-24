'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),cp=require('node:child_process');
const {scan}=require('../src/engine');
const {gate}=require('../src/triage');
const {writeReports}=require('../src/report');
const fixture=(t,files)=>{const root=fs.mkdtempSync(path.join(os.tmpdir(),'kayfabe-coverage-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));for(const [name,raw]of Object.entries(files)){fs.mkdirSync(path.dirname(path.join(root,name)),{recursive:true});fs.writeFileSync(path.join(root,name),raw);}return root;};

test('Rust/C files remain explicitly unsupported despite a passing severity gate',async t=>{
 const root=fixture(t,{'main.rs':'fn main() {}','helper.c':'int main(void) { return 0; }'}),r=await scan(root);
 assert.equal(r.coverage.schema,'kayfabe/coverage@1');
 assert.equal(r.coverage.source.status,'incomplete');
 assert.equal(r.coverage.source.unsupportedFiles,2);
 assert.equal(r.coverage.source.languages.rust.analyzedFiles,0);
 assert.equal(r.stats.languages.rust,1);
 assert.equal(gate(r).passed,true);
 assert.ok(r.warnings.some(w=>w.includes('Incomplete coverage')));
 assert.equal(r.findings.length,0);
});

test('size limits and empty inputs cannot satisfy a coverage requirement',async t=>{
 const {coverageGate}=require('../src/coverage');
 const root=fixture(t,{'main.rs':' '.repeat(1500)}),r=await scan(root,{maxFileSize:1000});
 assert.equal(r.coverage.source.status,'incomplete');
 assert.equal(coverageGate(r,true).passed,false);
 assert.equal(coverageGate({findings:[]},true).passed,false);
 const empty=await scan(fixture(t,{'README.md':'No source here'}));
 assert.equal(empty.coverage.source.status,'not-applicable');
 assert.equal(coverageGate(empty,true).passed,false);
});

test('Cargo inventory and advisory breadth are separate from unsupported Rust analysis',async t=>{
 const r=await scan(fixture(t,{'main.rs':'fn main() {}','Cargo.toml':'[dependencies]\nh2 = "0.4"'}));
 assert.equal(r.coverage.inventory.cargo.status,'complete');
 assert.equal(r.coverage.inventory.cargo.resolvedPackages,0);
 assert.equal(r.dependencyInventory[0].version,null);
 assert.equal(r.coverage.advisories.status,'limited');
 assert.equal(r.coverage.advisories.online.status,'not-requested');
 assert.ok(r.coverage.advisories.cargoSnapshot.date);
});

test('all reports expose incomplete coverage separately from findings',async t=>{
 const {coverageGate}=require('../src/coverage');
 const r=await scan(fixture(t,{'main.rs':'fn main() {}'})),out=fixture(t,{});
 const files=writeReports(r,out,{gate:gate(r),coverageGate:coverageGate(r,true)});
 const json=JSON.parse(fs.readFileSync(files['findings.json'],'utf8'));
 assert.equal(json.gate.passed,true);assert.equal(json.coverageGate.passed,false);
 const sarif=JSON.parse(fs.readFileSync(files['results.sarif'],'utf8'));
 assert.equal(sarif.runs[0].properties.coverage.source.status,'incomplete');
 assert.equal(sarif.runs[0].results.length,0);
 assert.match(fs.readFileSync(files['junit.xml'],'utf8'),/failure type="COVERAGE"/);
 for(const format of ['md','html'])assert.match(fs.readFileSync(files['report.'+format],'utf8'),/Incomplete coverage/);
});

test('CLI coverage is opt-in, independently enforced, and no-gate is explicit',t=>{
 const root=fixture(t,{'main.rs':'fn main() {}'}),cli=path.resolve(__dirname,'../bin/kayfabe.js');
 const run=(extra=[])=>cp.spawnSync(process.execPath,[cli,'scan',root,'--out',path.join(root,'out'),'--format','json','--quiet',...extra],{encoding:'utf8',env:{...process.env,KAYFABE_NO_UPDATE_CHECK:'1'},windowsHide:true});
 assert.equal(run().status,0);
 assert.equal(run(['--require-coverage']).status,1);
 assert.equal(run(['--require-coverage','--no-gate']).status,0);
});

test('supported source checks pass independently of limited advisories; vendor exclusions are disclosed',async t=>{
 const {coverageGate}=require('../src/coverage');
 const r=await scan(fixture(t,{'main.js':'console.log("ok");','public/lib/jquery.js':'function example() {}','test/old.c':'int f(void) {return 1;}'}));
 assert.equal(r.coverage.source.status,'complete');
 assert.equal(r.coverage.source.files,1);
 assert.equal(coverageGate(r,true).passed,true);
 assert.equal(r.coverage.scope.excludedVendored,1);
 assert.equal(r.coverage.scope.excludedTests,1);
});

test('MCP audit/report return coverage and enforce a separate requested requirement',async t=>{
 const {callTool}=require('../src/mcp/server');
 const root=fixture(t,{'main.rs':'fn main() {}'}),out=fixture(t,{});
 const r=await callTool('appsec_audit',{target:root,out,require_coverage:true});
 assert.equal(r.gate.passed,true);assert.equal(r.coverageGate.passed,false);assert.equal(r.passed,false);
 const report=await callTool('appsec_report',{report_dir:out,require_coverage:true});
 assert.equal(report.analysisCoverage.source.status,'incomplete');assert.equal(report.passed,false);
});

test('CLI report/gate do not infer coverage for legacy reports',async t=>{
 const root=fixture(t,{'main.js':'console.log("ok")'}),r=await scan(root),out=fixture(t,{});
 delete r.coverage;fs.writeFileSync(path.join(out,'findings.json'),JSON.stringify(r));
 for(const command of ['report','gate']) {
  const child=cp.spawnSync(process.execPath,[path.resolve(__dirname,'../bin/kayfabe.js'),command,out,'--require-coverage','--quiet'],{encoding:'utf8',env:{...process.env,KAYFABE_NO_UPDATE_CHECK:'1'},windowsHide:true});
  assert.equal(child.status,1,child.stderr);
 }
});

test('read failures are incomplete even if another source file was analyzed',async t=>{
 const root=fixture(t,{'main.js':'console.log("ok")','other.rs':'fn main() {}'}),original=fs.readFileSync;
 t.mock.method(fs,'readFileSync',function(file,...args){if(String(file)===path.join(root,'other.rs'))throw Error('denied');return original.call(this,file,...args);});
 const r=await scan(root);
 assert.equal(r.coverage.source.status,'incomplete');assert.equal(r.coverage.scope.limits.readFailures,1);
});
