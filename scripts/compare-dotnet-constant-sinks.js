'use strict';

const fs = require('node:fs');
const path = require('node:path');

const beforePath = path.resolve(process.argv[2] || 'appsec-reports/benchmarks/fp-roadmap-baseline/benchmark.json');
const afterPath = path.resolve(process.argv[3] || 'appsec-reports/benchmarks/fp-roadmap-final/benchmark.json');
const outPath = path.resolve(process.argv[4] || 'docs/benchmarks/dotnet-constant-sinks-comparison.json');
const before = JSON.parse(fs.readFileSync(beforePath, 'utf8'));
const after = JSON.parse(fs.readFileSync(afterPath, 'utf8'));

for (const key of ['inputSha256', 'expectedSha256', 'labelsSha256', 'sourceArchiveSha256']) {
  if (before.dataset[key] !== after.dataset[key]) throw new Error(`dataset ${key} changed`);
}
if (JSON.stringify(before.policy) !== JSON.stringify(after.policy)) throw new Error('scoring policy changed');
if (before.cases.length !== after.cases.length) throw new Error('scored case count changed');

const beforeById = new Map(before.cases.map(item => [item.id, item]));
const afterById = new Map(after.cases.map(item => [item.id, item]));
if (beforeById.size !== before.cases.length || afterById.size !== after.cases.length) throw new Error('duplicate benchmark unit id');
const transitions = { fpToTn: [], tpToFn: [], tnToFp: [], fnToTp: [] };
for (const [id, oldCase] of beforeById) {
  const next = afterById.get(id);
  if (!next || oldCase.cwe !== next.cwe || oldCase.vulnerable !== next.vulnerable || JSON.stringify(oldCase.regions) !== JSON.stringify(next.regions)) {
    throw new Error(`benchmark label changed for ${id}`);
  }
  const key = `${oldCase.outcome}To${next.outcome[0].toUpperCase()}${next.outcome.slice(1)}`;
  if (transitions[key]) transitions[key].push(id);
}

const result = {
  schema: 'kayfabe-dotnet-constant-sinks-comparison@1',
  dataset: {
    name: after.dataset.name,
    version: after.dataset.version,
    inputSha256: after.dataset.inputSha256,
    labelsSha256: after.dataset.labelsSha256,
    unitManifestSha256: after.dataset.unitManifestSha256,
    cases: after.totals.cases,
  },
  before: { sourceSha256: before.tool.sourceSha256, totals: before.totals, byCwe: before.byCwe },
  after: { sourceSha256: after.tool.sourceSha256, totals: after.totals, byCwe: after.byCwe },
  transitions: Object.fromEntries(Object.entries(transitions).map(([key, ids]) => [key, { count: ids.length, ids }])),
};
fs.mkdirSync(path.dirname(outPath), { recursive: true });
fs.writeFileSync(outPath, JSON.stringify(result, null, 2) + '\n');
process.stdout.write(`${JSON.stringify({ outPath, transitions: Object.fromEntries(Object.entries(result.transitions).map(([key, value]) => [key, value.count])) })}\n`);
