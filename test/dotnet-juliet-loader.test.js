'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { loadJulietCSharpUnits } = require('../src/dotnet-juliet-units');
const manifest = require('../docs/benchmarks/dotnet-juliet-cross-file-units.json');

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kayfabe-juliet-csharp-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const dir = 'src/testcases/CWE89_SQL_Injection/s01';
  fs.mkdirSync(path.join(root, dir), { recursive: true });
  return { root, dir };
}

test('C# Juliet labels include both polarity regions across 22a/22b files and skip unlabelled helpers', t => {
  const { root, dir } = fixture(t);
  const source = `class Sample {\n  public void Bad() { RunBad(); }\n  public void Good() { RunGood(); }\n}`;
  const files = [`${dir}/CWE89_SQL_Injection__Flow_22a.cs`, `${dir}/CWE89_SQL_Injection__Flow_22b.cs`, `${dir}/Program.cs`, `${dir}/CWE89_SQL_Injection__Flow_Class_Helper.cs`];
  files.slice(0, 2).forEach(file => fs.writeFileSync(path.join(root, file), source));
  fs.writeFileSync(path.join(root, files[2]), 'class Program { static void Main() {} }');
  fs.writeFileSync(path.join(root, files[3]), 'class Helper { public string ToString() { return "helper"; } }');
  const result = loadJulietCSharpUnits(root, files, manifest);
  assert.equal(result.units.length, 2);
  assert.deepEqual(result.units.map(unit => unit.labelIds.length), [2, 2]);
  assert.deepEqual(result.labels.map(label => label.regions.length), [2, 2]);
  assert.match(result.labelsSha256, /^[a-f0-9]{64}$/);
  assert.equal(result.supportFilesWithoutPolarity.length, 1);
});

test('the Juliet 81 bad, base, and good files form separate polarity units without labeling the base class', t => {
  const { root, dir } = fixture(t);
  const manifest81 = structuredClone(manifest);
  manifest81.crossFileVariants.at(-1).variants = ['81_bad', '81_base', '81_goodB2G', '81_goodG2B'];
  const files = [
    `${dir}/CWE89_SQL_Injection__Flow_81_bad.cs`,
    `${dir}/CWE89_SQL_Injection__Flow_81_base.cs`,
    `${dir}/CWE89_SQL_Injection__Flow_81_goodB2G.cs`,
    `${dir}/CWE89_SQL_Injection__Flow_81_goodG2B.cs`,
  ];
  fs.writeFileSync(path.join(root, files[0]), 'class BadCase { public void Bad() { RunBad(); } }');
  fs.writeFileSync(path.join(root, files[1]), 'abstract class BaseCase { public abstract void Action(); }');
  fs.writeFileSync(path.join(root, files[2]), 'class GoodCase { public void GoodB2G() { RunSafe(); } }');
  fs.writeFileSync(path.join(root, files[3]), 'class GoodCase { public void GoodG2B() { RunSafe(); } }');
  const result = loadJulietCSharpUnits(root, files, manifest81);
  assert.equal(result.units.length, 2);
  assert.deepEqual(result.units.map(unit => unit.labelIds.length), [1, 2]);
  assert.deepEqual(result.labels.map(label => label.regions.length), [1, 2]);
  assert.equal(result.supportFilesWithoutPolarity.length, 1);
});

