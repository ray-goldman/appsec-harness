'use strict';
const fs = require('node:fs');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { toolHash } = require('../src/benchmark');
const datasets = [
  ['owasp', 'owasp-java-1.2'],
  ['juliet', 'juliet-java-1.3'],
  ['sard', 'sard-115'],
  ['cve', 'cve-fixes'],
];
const sourceSha256 = toolHash();
const result = { schema: 'appsec-harness/js-python-helpers-comparison@1', sourceSha256, datasets: [] };
for (const [name, stem] of datasets) {
  const before = JSON.parse(fs.readFileSync(`appsec-reports/benchmarks/format-arrays-${name}/benchmark.json`));
  const baseline = JSON.parse(fs.readFileSync(`docs/benchmarks/${stem}-format-arrays.json`));
  const after = JSON.parse(fs.readFileSync(`appsec-reports/benchmarks/js-python-helpers-${name}/benchmark.json`));
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
  fs.writeFileSync(`docs/benchmarks/${stem}-js-python-helpers.json`, JSON.stringify(aggregate, null, 2) + '\n');
  result.datasets.push(row);
}
fs.writeFileSync('docs/benchmarks/js-python-helpers-comparison.json', JSON.stringify(result, null, 2) + '\n');
for (const d of result.datasets) console.log(d.dataset, JSON.stringify({
  before: d.before, after: d.after, transitions: d.transitions,
  lost: d.lostTruePositiveCases, newFalsePositives: d.newFalsePositiveCases, localized: d.localized,
}));

const before = JSON.parse(fs.readFileSync('appsec-reports/benchmarks/js-python-helpers-before.json'));
const after = JSON.parse(fs.readFileSync('appsec-reports/benchmarks/js-python-helpers-after.json'));
const committed = JSON.parse(fs.readFileSync('docs/benchmarks/supplied-apps-format-arrays.json'));
assert.equal(before.sourceSha256, '101cc0e4a46731dc5c8247536c06aaf6a5132a70896699ddd9d47d8028015ab9');
assert.equal(after.sourceSha256, sourceSha256);
assert.deepEqual(before.totals, committed.totals);
assert.deepEqual(before.apps, committed.apps);
for (const key of ['inputSha256', 'evaluatorSha256']) {
  assert.equal(before[key], after[key], key);
}
assert.equal(before.inputSha256, committed.inputSha256);
const evaluatorBytes = fs.readFileSync('scripts/score-supplied-apps.js');
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
assert.equal(hash(evaluatorBytes), before.evaluatorSha256);
// The prior report used LF; this baseline was measured from a CRLF checkout.
// Require exact normalized source identity, not just equivalent scores.
const evaluatorLfSha256 = hash(evaluatorBytes.toString('utf8').replace(/\r\n/g, '\n'));
assert.equal(evaluatorLfSha256, committed.evaluatorSha256);
assert.deepEqual(before.policy, after.policy);
assert.deepEqual(before.policy, committed.policy);
assert.equal(before.apps.length, after.apps.length);
const transitions = {}, corrected = [], lost = [], added = [];
for (const app of before.apps) {
  const next = after.apps.find(a => a.app === app.app);
  assert.ok(next, `missing app ${app.app}`);
  assert.equal(next.unscoredManifestLabels, app.unscoredManifestLabels);
  assert.equal(next.cases.length, app.cases.length);
  const cases = new Map(next.cases.map(c => [c.id, c]));
  assert.equal(cases.size, app.cases.length);
  for (const c of app.cases) {
    const n = cases.get(c.id);
    assert.ok(n, `missing case ${c.id}`);
    for (const key of ['file', 'line', 'vulnerable', 'cwe', 'label']) assert.equal(n[key], c[key]);
    const transition = `${c.outcome}->${n.outcome}`;
    transitions[transition] = (transitions[transition] || 0) + 1;
    if (transition === 'fp->tn') corrected.push(`${app.app}/${c.id}`);
    if (transition === 'tp->fn') lost.push(`${app.app}/${c.id}`);
    if (transition === 'tn->fp') added.push(`${app.app}/${c.id}`);
  }
}
assert.deepEqual(lost, [], 'lost supplied true positives');
assert.deepEqual(added, [], 'new supplied false positives');
const supplied = {
  ...after, archive: committed.archive,
  before: { gitCommit: 'a99906e964898e87fd5826cd783069bfaed8f016', sourceSha256: before.sourceSha256,
    measuredAt: before.measuredAt, totals: before.totals },
  evaluatorIdentity: { priorLfSha256: committed.evaluatorSha256, currentLfSha256: evaluatorLfSha256,
    beforeAndAfterByteSha256: before.evaluatorSha256, note: 'Prior LF source and current CRLF source match after newline normalization; before/after bytes identical.' },
  comparison: { transitions, correctedFalsePositiveCases: corrected, lostTruePositiveCases: lost, newFalsePositiveCases: added },
};
fs.writeFileSync('docs/benchmarks/supplied-apps-js-python-helpers.json', JSON.stringify(supplied, null, 2) + '\n');
console.log('Supplied apps:', JSON.stringify({ totals: supplied.totals, ...supplied.comparison }));
