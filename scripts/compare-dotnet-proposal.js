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
const result = { schema: 'appsec-harness/dotnet-proposal-comparison@1', sourceSha256, datasets: [] };
for (const [name, stem] of datasets) {
  const before = JSON.parse(fs.readFileSync(`appsec-reports/benchmarks/dotnet-secrets-${name}/benchmark.json`));
  const baseline = JSON.parse(fs.readFileSync(`docs/benchmarks/${stem}-dotnet-secrets.json`));
  const after = JSON.parse(fs.readFileSync(`appsec-reports/benchmarks/dotnet-proposal-final-${name}/benchmark.json`));
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
  fs.writeFileSync(`docs/benchmarks/${stem}-dotnet-proposal.json`, JSON.stringify(aggregate, null, 2) + '\n');
  result.datasets.push(row);
}
fs.writeFileSync('docs/benchmarks/dotnet-proposal-comparison.json', JSON.stringify(result, null, 2) + '\n');
for (const d of result.datasets) console.log(d.dataset, JSON.stringify({
  before: d.before, after: d.after, transitions: d.transitions,
  lost: d.lostTruePositiveCases, newFalsePositives: d.newFalsePositiveCases, localized: d.localized,
}));

const before = JSON.parse(fs.readFileSync('appsec-reports/benchmarks/dotnet-secrets-after.json'));
const after = JSON.parse(fs.readFileSync('appsec-reports/benchmarks/dotnet-proposal-after.json'));
const committed = JSON.parse(fs.readFileSync('docs/benchmarks/supplied-apps-dotnet-secrets.json'));
assert.equal(before.sourceSha256, '0c82433af17a5fcc07eac9efdfa41caa4b0389045fc05046e44999dc7807b29b');
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
assert.equal(before.evaluatorSha256, committed.evaluatorSha256);
assert.deepEqual(before.policy, after.policy);
assert.deepEqual(before.policy, committed.policy);
assert.equal(before.apps.length, after.apps.length);
const transitions = {}, corrected = [], lost = [], added = [], gained = [];
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
    if (transition === 'fn->tp') gained.push(`${app.app}/${c.id}`);
    if (transition === 'tp->fn') lost.push(`${app.app}/${c.id}`);
    if (transition === 'tn->fp') added.push(`${app.app}/${c.id}`);
  }
}
assert.deepEqual(lost, [], 'lost supplied true positives');
assert.deepEqual(added, [], 'new supplied false positives');
const supplied = {
  ...after, archive: committed.archive,
  before: { gitCommit: '3e0b67fe21d606e9b11f014eb6d660b6cffa0848', sourceSha256: before.sourceSha256,
    measuredAt: before.measuredAt, totals: before.totals },
  comparison: { transitions, gainedTruePositiveCases: gained, correctedFalsePositiveCases: corrected, lostTruePositiveCases: lost, newFalsePositiveCases: added },
};
fs.writeFileSync('docs/benchmarks/supplied-apps-dotnet-proposal.json', JSON.stringify(supplied, null, 2) + '\n');
console.log('Supplied apps:', JSON.stringify({ totals: supplied.totals, ...supplied.comparison }));

// The archive's own scorer is not executed. Reuse the established source-line
// scorer, with unchanged labels and archive content on both sides.
const proposalBefore = JSON.parse(fs.readFileSync('appsec-out/claude-dotnet-review/before.json'));
const proposalAfter = JSON.parse(fs.readFileSync('appsec-out/claude-dotnet-review/after.json'));
// Switching to merged main changed some checkout line endings. Reproduce the
// original byte hash from PR #15 and independently rerun that baseline.
assert.equal(proposalBefore.sourceSha256, '3f64530eeebf7085f0e4bc967ebdac79528933579d7d9ac4c1a5b25cafae69ee');
const verifiedBefore = JSON.parse(fs.readFileSync('appsec-out/claude-dotnet-review/before-verified.json'));
const baselineVerification = JSON.parse(fs.readFileSync('appsec-out/claude-dotnet-review/baseline-verification.json'));
assert.equal(baselineVerification.gitCommit, '3e0b67fe21d606e9b11f014eb6d660b6cffa0848');
assert.equal(baselineVerification.sourceSha256, proposalBefore.sourceSha256);
for (const key of ['sourceSha256', 'inputSha256', 'evaluatorSha256', 'policy', 'totals', 'apps']) {
  assert.deepEqual(verifiedBefore[key], proposalBefore[key], `reproduced proposal baseline ${key}`);
}
assert.equal(proposalAfter.sourceSha256, sourceSha256);
for (const key of ['inputSha256', 'evaluatorSha256']) assert.equal(proposalBefore[key], proposalAfter[key]);
assert.equal(proposalAfter.evaluatorSha256, hash(evaluatorBytes));
assert.deepEqual(proposalBefore.policy, proposalAfter.policy);
assert.equal(proposalBefore.apps.length, proposalAfter.apps.length);
const proposalChanges = [], proposalTransitions = {};
for (const app of proposalBefore.apps) {
  const next = proposalAfter.apps.find(a => a.app === app.app);
  assert.ok(next);
  assert.equal(app.unscoredManifestLabels, next.unscoredManifestLabels);
  assert.equal(app.cases.length, next.cases.length);
  const map = new Map(next.cases.map(c => [c.id, c]));
  assert.equal(map.size, app.cases.length);
  for (const c of app.cases) {
    const n = map.get(c.id);
    assert.ok(n);
    for (const key of ['file', 'line', 'vulnerable', 'cwe', 'label']) assert.equal(c[key], n[key]);
    const transition = `${c.outcome}->${n.outcome}`;
    proposalTransitions[transition] = (proposalTransitions[transition] || 0) + 1;
    assert.notEqual(transition, 'tp->fn'); assert.notEqual(transition, 'tn->fp');
    if (c.outcome !== n.outcome) proposalChanges.push({ app: app.app, id: c.id, transition, matches: n.matches });
  }
}
const appAggregate = report => ({
  measuredAt: report.measuredAt, sourceSha256: report.sourceSha256,
  inputSha256: report.inputSha256, evaluatorSha256: report.evaluatorSha256,
  totals: report.totals,
  apps: report.apps.map(app => ({ app: app.app, totals: app.totals,
    findings: app.findings, unscoredManifestLabels: app.unscoredManifestLabels,
    unmatchedFindings: app.unmatched.length })),
});
const proposal = {
  schema: 'kayfabe/dotnet-proposal-apps-comparison@1',
  archiveSha256: '389c0a4433748bfd9078c9c06f75ebd645351a45ef82af5834815a15abec51ee',
  proposalCommit: '854097a84c944d7deb22991797ba7c1142928890',
  proposalBase: '12ea56f8c7c9ddba5caba4b663521e2f2fef8c3b',
  baselineCommit: '3e0b67fe21d606e9b11f014eb6d660b6cffa0848',
  baselineVerification,
  policy: proposalAfter.policy,
  limitations: 'Author-written apps and rules from the same proposal; no independent held-out claim. Manifest labels remain unscored. Unmatched findings are unclassified.',
  before: appAggregate(proposalBefore), after: appAggregate(proposalAfter),
  comparison: { transitions: proposalTransitions, changes: proposalChanges },
};
fs.writeFileSync('docs/benchmarks/claude-dotnet-apps-comparison.json', JSON.stringify(proposal, null, 2) + '\n');
console.log('Proposal apps:', JSON.stringify({ before: proposalBefore.totals, after: proposalAfter.totals, transitions: proposalTransitions }));
