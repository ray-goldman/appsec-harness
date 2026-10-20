'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const sourceDir = 'src/main/java/org/owasp/benchmark/testcode';
const sourcePath = (id) => `${sourceDir}/${id}.java`;
const csv = '# test name, category, real vulnerability, cwe, Benchmark version: 1.2\n' +
  'BenchmarkTest00001,crypto,true,327\nBenchmarkTest00002,crypto,false,327\n';

function fixture(t) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'appsec-benchmark-'));
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  const root = path.join(base, 'dataset');
  fs.mkdirSync(path.join(root, sourceDir), { recursive: true });
  fs.writeFileSync(path.join(root, 'expectedresults-1.2.csv'), csv);
  fs.writeFileSync(path.join(root, sourcePath('BenchmarkTest00001')),
    'class Weak { void f() { Cipher.getInstance("DES/ECB/PKCS5Padding"); } }\n');
  fs.writeFileSync(path.join(root, sourcePath('BenchmarkTest00002')),
    'class Safe { void f() { Cipher.getInstance("AES/GCM/NoPadding"); } }\n');
  return { base, root, out: path.join(base, 'report') };
}

test('CLI writes an independent benchmark report and keeps source out of it', (t) => {
  const { root, out } = fixture(t);
  const result = spawnSync(process.execPath, [
    path.join(__dirname, '../bin/appsec.js'), 'benchmark', 'owasp-java', root,
    '--out', out, '--dataset-revision', 'a'.repeat(40), '--json',
  ], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  const stdout = JSON.parse(result.stdout);
  const report = JSON.parse(fs.readFileSync(path.join(out, 'benchmark.json'), 'utf8'));
  assert.equal(stdout.totals.cases, 2);
  assert.equal(report.totals.tp, 1);
  assert.equal(report.totals.tn, 1);
  assert.equal(report.dataset.revision, 'a'.repeat(40));
  assert.match(report.dataset.inputSha256, /^[a-f0-9]{64}$/);
  assert.match(report.tool.sourceSha256, /^[a-f0-9]{64}$/);
  assert.equal(report.scan.options.includeTests, true);
  assert.equal(report.scan.options.minConfidence, 'low');
  assert.equal(report.scan.options.osv, false);
  assert.ok(!JSON.stringify(report).includes('Cipher.getInstance'));
  assert.match(fs.readFileSync(path.join(out, 'benchmark.md'), 'utf8'), /CWE-327/);
});

test('OWASP CSV parsing accepts BOM and CRLF but rejects corrupt labels', () => {
  const { parseExpectedResults } = require('../src/benchmark');
  const parsed = parseExpectedResults('\ufeff' + csv.replace(/\n/g, '\r\n'));
  assert.equal(parsed.version, '1.2');
  assert.equal(parsed.cases.length, 2);
  assert.deepEqual(parsed.cases[0], {
    id: 'BenchmarkTest00001', category: 'crypto', vulnerable: true,
    cwe: 327, file: sourcePath('BenchmarkTest00001'),
  });
  for (const invalid of [
    '', '# no rows', csv + 'BenchmarkTest00001,crypto,false,327\n',
    'BenchmarkTest00001,sqli,maybe,89', 'BenchmarkTest00001,sqli,true,0',
    '../../secret,sqli,true,89', 'BenchmarkTest00001,sqli,true,89,extra',
  ]) assert.throws(() => parseExpectedResults(invalid));
});

test('scoring counts every labeled case once and requires the exact path and CWE', () => {
  const { parseExpectedResults, scoreBenchmark } = require('../src/benchmark');
  const labels = parseExpectedResults([
    'BenchmarkTest00001,sqli,true,89', 'BenchmarkTest00002,sqli,true,89',
    'BenchmarkTest00003,sqli,false,89', 'BenchmarkTest00004,sqli,false,89',
    'BenchmarkTest00005,cmdi,true,78', 'BenchmarkTest00006,cmdi,false,78',
  ].join('\n')).cases;
  const hit = (id, cwe, overrides = {}) => ({
    file: sourcePath(id), cwe: [cwe], status: 'open', ruleId: 'EXAMPLE', line: 4, ...overrides,
  });
  const scored = scoreBenchmark(labels, [
    hit('BenchmarkTest00001', 89), hit('BenchmarkTest00001', 89, { line: 5 }),
    hit('BenchmarkTest00003', 89),
    hit('BenchmarkTest00002', 78), // Wrong CWE cannot earn credit.
    hit('BenchmarkTest00005', 78, { file: 'helpers/BenchmarkTest00005.java' }),
    hit('BenchmarkTest00006', 78, { status: 'suppressed' }),
  ]);
  assert.deepEqual(scored.totals, {
    cases: 6, tp: 1, fn: 2, fp: 1, tn: 2,
    truePositiveRate: 1 / 3, falsePositiveRate: 1 / 3, precision: 1 / 2,
  });
  assert.deepEqual(scored.byCwe.find((x) => x.cwe === 89), {
    cwe: 89, cases: 4, tp: 1, fn: 1, fp: 1, tn: 1,
    truePositiveRate: 0.5, falsePositiveRate: 0.5, precision: 0.5,
  });
  assert.equal(scored.byCwe.find((x) => x.cwe === 78).fn, 1);
  assert.equal(scored.unscoredFindings.wrongCwe, 1);
  assert.equal(scored.unscoredFindings.unlabeledFile, 1);
  assert.equal(scored.unscoredFindings.notOpen, 1);
  assert.equal(scored.cases[0].prediction, true);
});

test('undefined rates are null and unsupported CWEs stay in the denominator', () => {
  const { parseExpectedResults, scoreBenchmark } = require('../src/benchmark');
  const negative = parseExpectedResults('BenchmarkTest00001,trustbound,false,501').cases;
  const positive = parseExpectedResults('BenchmarkTest00001,trustbound,true,501').cases;
  assert.deepEqual(scoreBenchmark(negative, []).totals, {
    cases: 1, tp: 0, fp: 0, tn: 1, fn: 0,
    truePositiveRate: null, falsePositiveRate: 0, precision: null,
  });
  const missed = scoreBenchmark(positive, []).totals;
  assert.equal(missed.fn, 1);
  assert.equal(missed.truePositiveRate, 0);
  assert.equal(missed.falsePositiveRate, null);
});

test('missing and scanner-skipped cases abort rather than becoming true negatives', async (t) => {
  const { runBenchmark } = require('../src/benchmark');
  const { root, out } = fixture(t);
  const file = path.join(root, sourcePath('BenchmarkTest00002'));
  fs.unlinkSync(file);
  await assert.rejects(runBenchmark(root, { out }), /case.*missing|missing.*case/i);
  fs.writeFileSync(file, 'x'.repeat(1024 * 1024 + 1));
  await assert.rejects(runBenchmark(root, { out }), /skipped|scan coverage/i);
  assert.equal(fs.existsSync(out), false);
});

test('linked case directories are refused', async (t) => {
  const { runBenchmark } = require('../src/benchmark');
  const { root, base, out } = fixture(t);
  const original = path.join(root, sourceDir);
  const moved = path.join(base, 'linked-cases');
  fs.renameSync(original, moved);
  fs.symlinkSync(moved, original, process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(runBenchmark(root, { out }), /link/i);
  await assert.rejects(runBenchmark(root, { out, expected: '../outside.csv' }), /inside|relative/i);
});

test('expected-results paths cannot traverse directory links', async (t) => {
  const { runBenchmark } = require('../src/benchmark');
  const { root, base, out } = fixture(t);
  const labels = path.join(base, 'labels');
  fs.mkdirSync(labels);
  fs.writeFileSync(path.join(labels, 'expected.csv'), csv);
  fs.symlinkSync(labels, path.join(root, 'metadata'), process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(runBenchmark(root, { out, expected: 'metadata/expected.csv' }), /link/i);
});

test('binary case files abort the measurement', async (t) => {
  const { runBenchmark } = require('../src/benchmark');
  const { root, out } = fixture(t);
  fs.writeFileSync(path.join(root, sourcePath('BenchmarkTest00002')), Buffer.alloc(1024));
  await assert.rejects(runBenchmark(root, { out }), /binary case/i);
});

test('output cannot overwrite a dataset or follow a junction into it', async (t) => {
  const { runBenchmark } = require('../src/benchmark');
  const { root, base } = fixture(t);
  await assert.rejects(runBenchmark(root, { out: path.join(root, 'reports') }), /output.*dataset/i);
  const linked = path.join(base, 'output-link');
  fs.symlinkSync(root, linked, process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(runBenchmark(root, { out: path.join(linked, 'reports') }), /output.*dataset|link/i);
});

test('input hashes change with source data and malformed revisions are rejected', async (t) => {
  const { runBenchmark } = require('../src/benchmark');
  const { root, out } = fixture(t);
  const first = await runBenchmark(root, { out });
  fs.appendFileSync(path.join(root, sourcePath('BenchmarkTest00001')), '// changed\n');
  const second = await runBenchmark(root, { out });
  assert.notEqual(first.dataset.inputSha256, second.dataset.inputSha256);
  assert.equal(first.dataset.expectedSha256, second.dataset.expectedSha256);
  await assert.rejects(runBenchmark(root, { out, revision: 'master' }), /revision/i);
});

test('replacing a report cannot overwrite a hard-linked source file', async (t) => {
  const { runBenchmark } = require('../src/benchmark');
  const { root, out } = fixture(t);
  const source = path.join(root, sourcePath('BenchmarkTest00001'));
  const before = fs.readFileSync(source);
  fs.mkdirSync(out);
  fs.linkSync(source, path.join(out, 'benchmark.json'));
  await runBenchmark(root, { out });
  assert.deepEqual(fs.readFileSync(source), before);
  assert.equal(JSON.parse(fs.readFileSync(path.join(out, 'benchmark.json'))).totals.cases, 2);
});

test('CLI reports malformed datasets as errors without emitting metrics', (t) => {
  const { root, out } = fixture(t);
  fs.writeFileSync(path.join(root, 'expectedresults-1.2.csv'), 'bad,csv\n');
  const result = spawnSync(process.execPath, [
    path.join(__dirname, '../bin/appsec.js'), 'benchmark', 'owasp-java', root, '--out', out,
  ], { encoding: 'utf8' });
  assert.equal(result.status, 2);
  assert.equal(fs.existsSync(path.join(out, 'benchmark.json')), false);
});
