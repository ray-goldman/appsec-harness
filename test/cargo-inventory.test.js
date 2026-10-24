'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { parseManifest, isManifest } = require('../src/supply/manifests');
const { analyzeSupplyChain, queryOsv } = require('../src/supply');
const registry = 'registry+https://github.com/rust-lang/crates.io-index';
const checksum = 'a'.repeat(64);
const lock = (source = registry, version = '0.3.25') => `version = 4\n[[package]]\nname = "h2"\nversion = "${version}"\n${source == null ? '' : `source = "${source}"\nchecksum = "${checksum}"\n`}`;

test('the offline Cargo snapshot ships the exact pinned upstream advisory bytes', () => {
  const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),snapshot=require('../src/supply/cargo-advisories.json');
  const advisory=snapshot.advisories[0],bytes=fs.readFileSync(path.join(__dirname,'../docs/provenance/rustsec/RUSTSEC-2024-0332.md'));
  assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'),advisory.provenance.sha256);
  assert.ok(bytes.toString('utf8').includes('patched = ["^0.3.26", ">= 0.4.4"]'));
  const osvBytes=fs.readFileSync(path.join(__dirname,'../docs/provenance/rustsec',advisory.provenance.osv.file)),osv=JSON.parse(osvBytes);
  assert.equal(crypto.createHash('sha256').update(osvBytes).digest('hex'),advisory.provenance.osv.sha256);
  assert.equal(osv.id,advisory.ids[0]);assert.equal(osv.withdrawn,undefined);
  const events=osv.affected.find(a=>a.package.name===advisory.name&&a.package.ecosystem==='crates.io').ranges[0].events;
  assert.deepEqual(advisory.ranges,events.flatMap((e,i)=>e.introduced?[{introduced:e.introduced,fixed:events[i+1].fixed}]:[]));
  assert.equal(snapshot.advisories.length,1);assert.equal(snapshot.license,'CC0-1.0');
});

test('Cargo lock retains exact identity, provenance and checksum; manifest values are requirements', () => {
  assert.equal(isManifest('src/Cargo.lock'), true);
  const parsed = parseManifest('Cargo.lock', lock());
  assert.deepEqual(parsed.deps.map(d => [d.eco,d.name,d.version,d.source,d.checksum,d.origin]), [['crates.io','h2','0.3.25',registry,checksum,'registry']]);
  const manifest = parseManifest('Cargo.toml', '[dependencies]\ntransport = { package = "h2", version = "0.3.25" }');
  assert.equal(manifest.deps[0].name, 'h2');
  assert.equal(manifest.deps[0].alias, 'transport');
  assert.equal(manifest.deps[0].version, null);
  assert.equal(manifest.deps[0].spec, '0.3.25');
});

test('Cargo lock is authoritative, preserving duplicate versions with different sources', () => {
  const raw = lock() + lock('registry+https://private.invalid/index','0.3.25').replace('version = 4\n','');
  const result = analyzeSupplyChain([{rel:'Cargo.toml',raw:'[dependencies]\nh2 = "0.3"'}, {rel:'Cargo.lock',raw}]);
  assert.equal(result.inventory.length, 2);
  assert.equal(result.findings.length, 1);
  assert.ok(result.inventory.every(d => d.version === '0.3.25'));
  assert.equal(result.inventory[1].publicRegistry, false);
});

test('Cargo workspace aliases inherit requirements and share only their visible workspace lock', () => {
  const result = analyzeSupplyChain([
    {rel:'Cargo.toml',raw:'[workspace]\nmembers = ["crates/*"]\n[workspace.dependencies]\ntransport = { package = "h2", version = "0.3" }'},
    {rel:'crates/web/Cargo.toml',raw:'[package]\nname="web"\nversion="1.0.0"\n[dependencies.transport]\nworkspace = true'},
    {rel:'Cargo.lock',raw:lock()+ '\n[[package]]\nname="web"\nversion="1.0.0"'},
    {rel:'unrelated/Cargo.toml',raw:'[dependencies]\nh2="0.4"'},
  ]);
  assert.equal(result.inventory.filter(d => d.name === 'h2' && d.version).length, 1);
  assert.equal(result.inventory.find(d => d.name === 'web').origin, 'workspace');
  assert.ok(result.inventory.some(d => d.file === 'unrelated/Cargo.toml' && d.spec === '0.4'));
  assert.ok(!result.cargo.inputs.find(d => d.file === 'crates/web/Cargo.toml').diagnostics.length);
});

test('Cargo rejects ambiguous/unsupported documents without fabricated dependency versions', () => {
  for (const raw of [lock()+'name="other"', 'version=9\n', 'version=4\n[[package]]\nname="h2"\nversion="bad"', '[dependencies]\nx = """unsupported"""', '[dependencies]\nx = '+ '['.repeat(40)+'1'+']'.repeat(40)]) {
    const parsed = parseManifest(raw.includes('[dependencies]') ? 'Cargo.toml' : 'Cargo.lock', raw);
    assert.ok(parsed.diagnostics.length, raw);
    assert.equal(parsed.deps.length, 0);
  }
  assert.equal({}.polluted, undefined);
  assert.ok(parseManifest('Cargo.toml','[__proto__]\npolluted=true').diagnostics.length);
});

test('Cargo strings, dotted tables, target dependencies and comments are read as data', () => {
  const parsed = parseManifest('Cargo.toml', `[target.'cfg(windows)'.dependencies]\ntransport = { package = 'h2', version = '0.4', features = [\n "stream", # comment\n] }\n[dependencies.local]\npath = '../local'\nversion = '1'\n`);
  assert.equal(parsed.diagnostics.length,0);
  assert.deepEqual(parsed.deps.map(d=>[d.name,d.spec,d.origin]).sort(),[['h2','0.4','registry'],['local','1','local']].sort());
});

test('offline Cargo advisory is exact and source-specific, and fixed versions stay quiet', () => {
  for (const [source,version,count] of [[registry,'0.3.25',1],[registry,'0.3.26',0],[registry,'0.4.3',1],[registry,'0.4.4',0],['git+https://example.invalid/h2#abc','0.3.25',0],[null,'0.3.25',0]]) {
    assert.equal(analyzeSupplyChain([{rel:'Cargo.lock',raw:lock(source,version)}]).findings.length,count);
  }
});

test('Cargo OSV queries exclude requirements, Git, local and private registry packages', async t => {
  const sent=[];
  t.mock.method(globalThis,'fetch',async (url,opts)=>{
    assert.equal(url,'https://api.osv.dev/v1/querybatch');
    sent.push(...JSON.parse(opts.body).queries);
    return {ok:true,json:async()=>({results:[{}]})};
  });
  const inputs=[registry,'registry+https://private.invalid/index','git+https://example.invalid/h2#abc',null].map((s,i)=>({rel:`p${i}/Cargo.lock`,raw:lock(s)}));
  const {inventory}=analyzeSupplyChain(inputs);
  assert.deepEqual(await queryOsv(inventory),[]);
  assert.deepEqual(sent,[{package:{name:'h2',ecosystem:'crates.io'},version:'0.3.25'}]);
});

test('Cargo metadata diagnostics and source fields redact URL credentials', () => {
  const parsed=parseManifest('Cargo.lock',lock('registry+https://user:password@private.invalid/index?token=secret'));
  assert.ok(!JSON.stringify(parsed).includes('password'));
  assert.ok(!JSON.stringify(parsed).includes('token=secret'));
  assert.equal(parsed.deps[0].publicRegistry,false);
});

test('unsupported table redefinitions and invalid dependency shapes report incomplete inventory', () => {
  for(const raw of ['x=[]\n[[x]]\nname="wrong"','[dependencies]\nh2={version=42}', '[target]\nwindows="wrong"', '[workspace]\nmembers="wrong"','[dependencies]\nh2={workspace="wrong"}']) {
    assert.ok(parseManifest('Cargo.toml',raw).diagnostics.length,raw);
  }
});

test('visible path members and explicit workspace locations inherit the shared lock', () => {
  const r=analyzeSupplyChain([
    {rel:'Cargo.toml',raw:'[workspace]\nmembers=["app"]\n[workspace.dependencies]\nh2="0.3"'},
    {rel:'app/Cargo.toml',raw:'[package]\nname="app"\nversion="1.0.0"\n[dependencies]\nhelper={path="../helper"}'},
    {rel:'helper/Cargo.toml',raw:'[package]\nname="helper"\nversion="1.0.0"\nworkspace=".."\n[dependencies]\nh2={workspace=true}'},
    {rel:'Cargo.lock',raw:lock()},
  ]);
  assert.equal(r.inventory.length,1);
  assert.ok(r.cargo.inputs.every(i=>!i.diagnostics.length));
});

test('Cargo OSV rejects invalid/mismatched details, pagination and oversized result claims', async t => {
  t.mock.method(globalThis,'fetch',async url=>({ok:true,json:async()=>url.endsWith('querybatch')?{results:[{vulns:[{id:'RUSTSEC-TEST'}],next_page_token:'more'}]}:{id:'RUSTSEC-TEST',affected:[{package:{name:'other',ecosystem:'crates.io'}}]}}));
  await assert.rejects(()=>queryOsv(analyzeSupplyChain([{rel:'Cargo.lock',raw:lock()}]).inventory),/incomplete|pagination|identity/i);
});

test('unresolved manifest source identities never emit source credentials as requirements', () => {
  const p=parseManifest('Cargo.toml','[dependencies]\nh2="https://user:password@host.invalid/?token=secret"');
  assert.ok(p.diagnostics.length);
  assert.ok(!JSON.stringify(p).includes('password'));
});

test('Cargo prerelease ordering follows SemVer, including labels meaningful in other ecosystems', () => {
  for(const [version,count] of [['0.3.26-post.1',1],['0.3.26+build.1',0],['0.4.4-rc.1',1],['0.4.4',0]])assert.equal(analyzeSupplyChain([{rel:'Cargo.lock',raw:lock(registry,version)}]).findings.length,count,version);
  assert.ok(parseManifest('Cargo.lock',lock(registry,'0.4.4-01')).diagnostics.length);
});

test('automatic path members share workspace inheritance without an explicit package.workspace', () => {
  const r=analyzeSupplyChain([
    {rel:'Cargo.toml',raw:'[workspace]\nmembers=["app"]\n[workspace.dependencies]\nh2="0.3"'},
    {rel:'app/Cargo.toml',raw:'[package]\nname="app"\nversion="1.0.0"\n[dependencies]\nhelper={path="../helper"}'},
    {rel:'helper/Cargo.toml',raw:'[package]\nname="helper"\nversion="1.0.0"\n[dependencies]\nh2={workspace=true}'},
    {rel:'Cargo.lock',raw:lock()},
  ]);
  assert.equal(r.inventory.length,1);
  assert.ok(r.cargo.inputs.every(i=>!i.diagnostics.length));
});

test('Cargo input count and byte budgets are reported rather than silently skipped', () => {
  const r=analyzeSupplyChain(Array.from({length:1001},(_,i)=>({rel:`p${i}/Cargo.toml`,raw:'[dependencies]\nh2="0.4"'})));
  assert.equal(r.cargo.inputs.length,1001);
  assert.equal(r.cargo.inputs.at(-1).status,'incomplete');
});

test('adversarial workspace globs finish within the scanner budget', () => {
  const cp=require('node:child_process'),path=require('node:path');
  const script=`const {analyzeSupplyChain}=require(process.argv[1]);const r=analyzeSupplyChain([{rel:'Cargo.toml',raw:'[workspace]\\nmembers=["'+'**/'.repeat(18)+'missing"]'},{rel:'a'.repeat(90)+'/Cargo.toml',raw:'[package]\\nname="app"\\nversion="1.0.0"'}]);if(!r.cargo.inputs.some(i=>i.diagnostics.length))process.exit(2);`;
  const child=cp.spawnSync(process.execPath,['-e',script,path.resolve(__dirname,'../src/supply')],{encoding:'utf8',windowsHide:true,timeout:5000});
  assert.equal(child.error,undefined);assert.equal(child.status,0,child.stderr);
});

test('missing workspace inputs and invalid declarations are incomplete, including inherited shapes', () => {
  for(const raw of ['[workspace]\nmembers=["missing"]','[package]\nname="app"\nversion="1.0.0"\nworkspace="../missing"','[dependencies]\nh2={}','[dependencies]\nh2={version="0.3",git="https://host.invalid/repo",path="../other"}','[workspace.dependencies]\nh2={version="0.3",git=true}\n[dependencies]\nh2={workspace=true}']) {
    const r=analyzeSupplyChain([{rel:'Cargo.toml',raw}]);assert.equal(r.cargo.inputs[0].status,'incomplete',raw);
  }
});

test('TOML dotted-key tables cannot be explicitly redefined', () => {
  for(const raw of ['dependencies.h2.version="0.3"\n[dependencies.h2]\noptional=true','dependencies.h2.version="0.3"\n[dependencies]\nother="1"'])assert.ok(parseManifest('Cargo.toml',raw).diagnostics.length,raw);
  assert.equal(parseManifest('Cargo.toml','dependencies.h2.version="0.3"\ndependencies.h2.optional=true').diagnostics.length,0);
});

test('offline Cargo prerelease boundaries agree with the pinned OSV conversion', () => {
  assert.equal(analyzeSupplyChain([{rel:'Cargo.lock',raw:lock(registry,'0.4.0-alpha.1')}]).findings.length,1);
  assert.equal(analyzeSupplyChain([{rel:'Cargo.lock',raw:lock(registry,'0.3.27-rc.1')}]).findings.length,0);
});

test('Cargo OSV queries deduplicate requests and retain every lockfile location',async t=>{
 let queries=0;
 t.mock.method(globalThis,'fetch',async (url,opts)=>{
  if(url.endsWith('querybatch')){queries+=JSON.parse(opts.body).queries.length;return {ok:true,json:async()=>({results:[{vulns:[{id:'RUSTSEC-TEST'}]}]})};}
  return {ok:true,json:async()=>({id:'RUSTSEC-TEST',affected:[{package:{name:'h2',ecosystem:'crates.io'}}]})};
 });
 const result=await queryOsv(analyzeSupplyChain(['one/Cargo.lock','two/Cargo.lock'].map(rel=>({rel,raw:lock()}))).inventory);
 assert.equal(queries,1);assert.deepEqual(result.map(f=>f.file).sort(),['one/Cargo.lock','two/Cargo.lock']);
});

test('false dependency tables and recursive workspace declarations report incomplete metadata', () => {
 for(const raw of ['dependencies=false','[target.foo]\ndependencies=false','workspace=false','[workspace.dependencies]\nh2={workspace=true}\n[dependencies]\nh2={workspace=true}'])assert.equal(analyzeSupplyChain([{rel:'Cargo.toml',raw}]).cargo.inputs[0].status,'incomplete',raw);
});

test('source redaction removes userinfo through the final authority separator', () => {
 const marker='SCANNER_ONLY_CREDENTIAL_TAIL';
 for(const source of [`git+https://user:first@${marker}@private.invalid/repo`,`git+ssh://user:first@${marker}@private.invalid/repo`]) {
  const p=parseManifest('Cargo.lock',lock(source));
  assert.ok(!JSON.stringify(p).includes(marker));
  assert.match(p.deps[0].source,/\[REDACTED\]@private\.invalid/);
 }
});

test('Cargo input budget bounds later ownership analysis as well as parsing', () => {
 const cp=require('node:child_process'),path=require('node:path');
 const script=`const {analyzeSupplyChain}=require(process.argv[1]);const r=analyzeSupplyChain(Array.from({length:50000},(_,i)=>({rel:'p'+i+'/Cargo.toml',raw:'[dependencies]\\nh2="0.4"'})));if(r.cargo.inputs.length!==50000||r.cargo.inputs.at(-1).status!=='incomplete')process.exit(2);`;
 const child=cp.spawnSync(process.execPath,['-e',script,path.resolve(__dirname,'../src/supply')],{encoding:'utf8',windowsHide:true,timeout:5000});
 assert.equal(child.error,undefined);assert.equal(child.status,0,child.stderr);
});

test('workspace-inherited path dependencies become automatic visible members', () => {
 const r=analyzeSupplyChain([
  {rel:'Cargo.toml',raw:'[workspace]\nmembers=["app"]\n[workspace.dependencies]\nhelper={path="helper"}\nh2="0.3"'},
  {rel:'app/Cargo.toml',raw:'[package]\nname="app"\nversion="1.0.0"\n[dependencies]\nhelper={workspace=true}'},
  {rel:'helper/Cargo.toml',raw:'[package]\nname="helper"\nversion="1.0.0"\n[dependencies]\nh2={workspace=true}'},
  {rel:'Cargo.lock',raw:lock()},
 ]);
 assert.equal(r.inventory.length,1);assert.ok(r.cargo.inputs.every(f=>f.status==='complete'));
});

test('Cargo OSV never sends a recognized secret used as an alleged public package identity',async t=>{
 const candidate='gh'+'p_'+'A'.repeat(36);
 const raw=lock().replace('name = "h2"',`name = "${candidate}"`);
 let called=false;t.mock.method(globalThis,'fetch',async()=>{called=true;return {ok:true,json:async()=>({results:[{}]})};});
 await assert.rejects(()=>queryOsv(analyzeSupplyChain([{rel:'Cargo.lock',raw}]).inventory),/credential|secret/i);
 assert.equal(called,false);
});
