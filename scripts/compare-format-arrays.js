'use strict';
const fs = require('node:fs');
const assert = require('node:assert/strict');
const { toolHash } = require('../src/benchmark');
const datasets = [
  ['owasp', 'owasp-java-1.2'],
  ['juliet', 'juliet-java-1.3'],
  ['sard', 'sard-115'],
  ['cve', 'cve-fixes'],
];
const sourceSha256 = toolHash();
const result = { schema: 'appsec-harness/java-format-arrays-comparison@1', sourceSha256, datasets: [] };
for (const [name, stem] of datasets) {
  const before = JSON.parse(fs.readFileSync(`appsec-reports/benchmarks/helper-sanitizer-${name}/benchmark.json`));
  const baseline = JSON.parse(fs.readFileSync(`docs/benchmarks/${stem}-helper-sanitizer.json`));
  const after = JSON.parse(fs.readFileSync(`appsec-reports/benchmarks/format-arrays-${name}/benchmark.json`));
  assert.deepEqual(before.totals, baseline.totals);
  assert.equal(before.tool.sourceSha256, baseline.tool.sourceSha256);
  for (const field of ['inputSha256', 'expectedSha256', 'manifestSha256']) {
    assert.equal(before.dataset[field], baseline.dataset[field], `baseline ${name} ${field}`);
  }
  assert.deepEqual(before.policy, baseline.policy, `baseline ${name} policy`);
  assert.equal(after.tool.sourceSha256, sourceSha256, `stale ${name}`);
  assert.equal(after.dataset.inputSha256, before.dataset.inputSha256);
  assert.equal(after.dataset.expectedSha256, before.dataset.expectedSha256);
  assert.equal(after.dataset.manifestSha256, before.dataset.manifestSha256);
  assert.deepEqual(after.policy, before.policy);
  assert.equal(after.totals.cases, before.totals.cases);
  const row = {
    dataset: name, inputSha256: after.dataset.inputSha256, policy: after.policy,
    beforeSourceSha256: before.tool.sourceSha256, afterSourceSha256: sourceSha256,
    before: before.totals, after: after.totals,
    beforeScanDurationMs: before.scan?.durationMs, afterScanDurationMs: after.scan?.durationMs,
    byCwe: after.byCwe.map(x => ({ cwe: x.cwe, before: before.byCwe.find(b => b.cwe === x.cwe), after: x })),
  };
  if (name !== 'cve') {
    const map = new Map(after.cases.map(x => [x.id, x]));
    assert.equal(map.size, before.cases.length);
    row.transitions = {};
    row.correctedFalsePositiveCases = [];
    row.lostTruePositiveCases = [];
    row.newFalsePositiveCases = [];
    for (const b of before.cases) {
      const a = map.get(b.id);
      assert.ok(a, `missing case ${b.id}`);
      const transition = `${b.outcome}->${a.outcome}`;
      row.transitions[transition] = (row.transitions[transition] || 0) + 1;
      if (transition === 'fp->tn') row.correctedFalsePositiveCases.push(b.id);
      if (transition === 'tp->fn') row.lostTruePositiveCases.push(b.id);
      if (transition === 'tn->fp') row.newFalsePositiveCases.push(b.id);
    }
  } else {
    const map = new Map(after.cases.map(x => [x.id, x]));
    assert.equal(map.size, before.cases.length);
    row.transitions = {};
    row.lostTruePositiveCases = [];
    row.newFalsePositiveCases = [];
    for (const b of before.cases) {
      const a = map.get(b.id);
      assert.ok(a, `missing CVE ${b.id}`);
      for (const revision of ['parent', 'fix']) {
        assert.deepEqual(a[revision].files, b[revision].files);
        const transition = `${b[revision].outcome}->${a[revision].outcome}`;
        row.transitions[transition] = (row.transitions[transition] || 0) + 1;
        if (transition === 'tp->fn') row.lostTruePositiveCases.push(`${b.id}/${revision}`);
        if (transition === 'tn->fp') row.newFalsePositiveCases.push(`${b.id}/${revision}`);
      }
    }
    assert.equal(after.localized.sha256, before.localized.sha256);
    assert.deepEqual(after.localized.policy, before.localized.policy);
    assert.deepEqual(after.localized.cases, before.localized.cases);
    row.beforePairs = before.pairs;
    row.afterPairs = after.pairs;
    row.localized = { policy: after.localized.policy, annotationSha256: after.localized.sha256,
      before: before.localized.totals, after: after.localized.totals,
      beforePairs: before.localized.pairs, afterPairs: after.localized.pairs };
  }
  assert.equal(row.lostTruePositiveCases.length, 0, `lost TP in ${name}`);
  assert.equal(row.newFalsePositiveCases.length, 0, `new FP in ${name}`);
  const { cases, ...aggregate } = after;
  if (baseline.provenance) aggregate.provenance = baseline.provenance;
  fs.writeFileSync(`docs/benchmarks/${stem}-format-arrays.json`, JSON.stringify(aggregate, null, 2) + '\n');
  result.datasets.push(row);
}
fs.writeFileSync('docs/benchmarks/java-format-arrays-comparison.json', JSON.stringify(result, null, 2) + '\n');
for (const d of result.datasets) console.log(d.dataset, JSON.stringify({
  before: d.before, after: d.after, transitions: d.transitions,
  lost: d.lostTruePositiveCases, newFalsePositives: d.newFalsePositiveCases, localized: d.localized,
}));

const suppliedBefore = JSON.parse(fs.readFileSync('appsec-reports/benchmarks/supplied-apps-before.json'));
const suppliedAfter = JSON.parse(fs.readFileSync('appsec-reports/benchmarks/supplied-apps-after.json'));
assert.equal(suppliedAfter.sourceSha256, sourceSha256, 'stale supplied-app scan');
// This baseline was taken after merging PR #5, from the Windows main checkout.
// It has its own byte identity; do not substitute the earlier four-run hash.
assert.equal(suppliedBefore.sourceSha256, 'd1c1bb209303c475a5130d0cf7e5a478ea9e23820bf88248c48e2864a3ae9be4');
assert.equal(suppliedBefore.inputSha256, suppliedAfter.inputSha256);
assert.equal(suppliedBefore.evaluatorSha256, suppliedAfter.evaluatorSha256);
assert.deepEqual(suppliedBefore.policy, suppliedAfter.policy);
assert.deepEqual(suppliedBefore.apps, suppliedAfter.apps, 'supplied-app cases changed');
const supplied = {
  ...suppliedAfter,
  archive: { name: 'appsec-benchmarks.zip',
    sha256: '3dab4cfd405e313ed80093560c3bf17cfb6f4ae5a33902da43a3054af9878c25' },
  before: { gitCommit: '4a3ad834a02995ccd4acd20230dff7a5cb47ae73',
    sourceSha256: suppliedBefore.sourceSha256, measuredAt: suppliedBefore.measuredAt, totals: suppliedBefore.totals },
  comparison: 'Every app, case outcome, match and unmatched finding unchanged; input and evaluator hashes identical',
};
fs.writeFileSync('docs/benchmarks/supplied-apps-format-arrays.json', JSON.stringify(supplied, null, 2) + '\n');
console.log('Supplied apps:', JSON.stringify(supplied.totals));
