'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { prepareDotnetJulietBenchmark } = require('../src/dotnet-juliet-benchmark');
const { runLabeled } = require('../src/benchmark-labeled');
const manifest = require('../docs/benchmarks/dotnet-juliet-cross-file-units.json');

test('C# Juliet preparation pins source, label, policy, and testcase unit hashes', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kayfabe-dotnet-juliet-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const dir = path.join(root, 'src/testcases/CWE89_SQL_Injection/s01');
  fs.mkdirSync(dir, { recursive: true });
  const source = 'class Sample {\n public void Bad() { RunBad(); }\n public void Good() { RunGood(); }\n}';
  fs.writeFileSync(path.join(dir, 'CWE89_SQL_Injection__Flow_22a.cs'), source);
  fs.writeFileSync(path.join(dir, 'CWE89_SQL_Injection__Flow_22b.cs'), source);
  const prepared = prepareDotnetJulietBenchmark(root, manifest);
  assert.equal(prepared.name, 'Juliet C# 1.3');
  assert.equal(prepared.labels.length, 2);
  assert.match(prepared.metadata.expectedSha256, /^[a-f0-9]{64}$/);
  assert.equal(prepared.metadata.sourceArchiveSha256, manifest.sourceArchiveSha256);
  assert.ok(prepared.policy.unit.includes('22a/b'));
  assert.equal(prepared.inputFiles.length, 2);
});

test('labeled benchmarks record the opt-in project-analysis scan mode', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kayfabe-dotnet-mode-'));
  const out = path.join(root, 'report');
  const dataset = path.join(root, 'dataset');
  fs.mkdirSync(dataset);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const source = 'class Sample { public void Good() { } }\n';
  fs.writeFileSync(path.join(dataset, 'Sample.cs'), source);
  const report = await runLabeled(dataset, { out, dotnetProjectAnalysis: true }, {
    name: 'test label set', source: 'test', version: '1', inputFiles: ['Sample.cs'], manifestFiles: [],
    labels: [{ cwe: 89, vulnerable: false, regions: [{ file: 'Sample.cs', startLine: 1, endLine: 1 }] }],
    regionsByFile: new Map([['Sample.cs', [{ file: 'Sample.cs', startLine: 1, endLine: 1 }]]]),
    policy: { id: 'test@1', unit: 'one sample', match: 'exact line', limitations: [] }, metadata: {},
  });
  assert.equal(report.scan.options.dotnetProjectAnalysis, true);
  assert.deepEqual(report.scan.options.dotnetProjectAnalysisLimits, { maxIterations: 8, maxEdges: 10000 });
  assert.equal(report.scan.stats.dotnetProject.summaryVersion, 1);
});

test('accuracy comparisons reject changed labels, provenance and incoherent outcomes', () => {
  const {compare}=require('../scripts/compare-dotnet-accuracy');
  const before={dataset:{inputSha256:'a'.repeat(64)},tool:{sourceSha256:'b'.repeat(64)},policy:{id:'test@1'},
    totals:{cases:1,tp:0,fp:1,tn:0,fn:0},cases:[{id:'safe',cwe:89,vulnerable:false,outcome:'fp'}]};
  const after=structuredClone(before);after.cases[0].outcome='tn';after.totals={cases:1,tp:0,fp:0,tn:1,fn:0};
  assert.equal(compare(before,after).transitions.fpToTn.count,1);
  const label=structuredClone(after);label.cases[0].cwe=78;assert.throws(()=>compare(before,label),/label/);
  const missing=structuredClone(after);delete missing.tool.sourceSha256;assert.throws(()=>compare(before,missing),/source/);
  const invalid=structuredClone(before);invalid.cases[0].outcome='tp';invalid.totals={cases:1,tp:1,fp:0,tn:0,fn:0};
  assert.throws(()=>compare(invalid,invalid),/polarity/);
  const policy=structuredClone(after);policy.policy.id='different';assert.throws(()=>compare(before,policy),/policy/);
  const options=structuredClone(after);options.scan={options:{dotnetProjectAnalysis:true}};
  assert.throws(()=>compare(before,options),/options/);
});
