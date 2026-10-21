'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { prepareDotnetJulietBenchmark } = require('../src/dotnet-juliet-benchmark');
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
