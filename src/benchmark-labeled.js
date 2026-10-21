'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { scan } = require('./engine');
const { walk } = require('./walker');
const { isProbablyBinary } = require('./util');
const { checkedFile, outputDirectory, hashInputs, toolHash, writeReportFile, SCAN_OPTIONS, metrics } = require('./benchmark');
const pkg = require('../package.json');
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');

function datasetRoot(directory) {
  if (typeof directory !== 'string' || !directory) throw new Error('benchmark dataset directory required');
  const root = fs.realpathSync(path.resolve(directory));
  if (!fs.statSync(root).isDirectory()) throw new Error('benchmark input must be a directory');
  return root;
}

// Enumerate independently of scanner exclusions so missing coverage cannot silently remove labels.
function inventory(root) {
  const files = [];
  function visit(rel, depth) {
    if (depth > 40) throw new Error('dataset directory depth exceeds 40');
    for (const entry of fs.readdirSync(path.join(root, rel), { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const name = rel ? `${rel}/${entry.name}` : entry.name;
      if (entry.isSymbolicLink()) throw new Error(`linked dataset input: ${name}`);
      if (entry.isDirectory()) visit(name, depth + 1);
      else if (entry.isFile()) files.push(name);
      else throw new Error(`non-regular dataset input: ${name}`);
      if (files.length > 150000) throw new Error('dataset exceeds 150000 files');
    }
  }
  visit('', 0);
  return files;
}

function readBounded(root, rel, max = 1024 * 1024) {
  const file = checkedFile(root, rel);
  if (fs.statSync(file).size > max) throw new Error(`input exceeds ${max} bytes: ${rel}`);
  return fs.readFileSync(file);
}

function scoreRegions(labels, findings) {
  const byFile = new Map(), matches = labels.map(() => []);
  labels.forEach((label, index) => {
    for (const region of label.regions) {
      if (!byFile.has(region.file)) byFile.set(region.file, []);
      byFile.get(region.file).push({ ...region, index, cwe: label.cwe });
    }
  });
  const unscoredFindings = { notOpen: 0, unlabeledFile: 0, wrongCwe: 0, outsideRegions: 0 };
  for (const finding of findings) {
    if (finding.status !== 'open') { unscoredFindings.notOpen++; continue; }
    const regions = byFile.get(finding.file.replace(/\\/g, '/'));
    if (!regions) { unscoredFindings.unlabeledFile++; continue; }
    const sameCwe = regions.filter((region) => finding.cwe.includes(region.cwe));
    if (!sameCwe.length) { unscoredFindings.wrongCwe++; continue; }
    const hit = new Set(sameCwe.filter((region) => finding.line >= region.startLine && finding.line <= region.endLine).map((region) => region.index));
    if (!hit.size) { unscoredFindings.outsideRegions++; continue; }
    for (const index of hit) matches[index].push({ ruleId: finding.ruleId, file: finding.file, line: finding.line });
  }
  const zero = () => ({ cases: 0, tp: 0, fp: 0, tn: 0, fn: 0 });
  const total = zero(), groups = new Map();
  const cases = labels.map((label, i) => {
    const prediction = matches[i].length > 0;
    const outcome = label.vulnerable ? (prediction ? 'tp' : 'fn') : (prediction ? 'fp' : 'tn');
    if (!groups.has(label.cwe)) groups.set(label.cwe, { cwe: label.cwe, ...zero() });
    const group = groups.get(label.cwe);
    total.cases++; total[outcome]++; group.cases++; group[outcome]++;
    return { ...label, prediction, outcome, matches: matches[i] };
  });
  return { totals: metrics(total), byCwe: [...groups.values()].sort((a, b) => a.cwe - b.cwe).map(metrics), unscoredFindings, cases };
}

function markdown(report) {
  const pct = (x) => x === null ? 'n/a' : `${(100 * x).toFixed(2)}%`;
  const row = (name, x) => `| ${name} | ${x.cases} | ${x.tp} | ${x.fp} | ${x.tn} | ${x.fn} | ${pct(x.truePositiveRate)} | ${pct(x.falsePositiveRate)} | ${pct(x.precision)} |`;
  return [
    `# ${report.dataset.name} measurement`, '',
    `Measured at: ${report.measuredAt}`,
    `Input SHA-256: \`${report.dataset.inputSha256}\``,
    `Labels SHA-256: \`${report.dataset.expectedSha256}\``,
    `Harness source SHA-256: \`${report.tool.sourceSha256}\``,
    `Harness: ${report.tool.version}; Node: ${report.runtime.node}; platform: ${report.runtime.platform}`,
    `Declared revision: ${report.dataset.revision || 'not supplied'} (not verified)`, '',
    ...(report.dataset.officialJuliet13Manifest ? [
      `Official Juliet manifest compatibility: ${report.dataset.redundantTestcaseClosings} redundant closing tags ignored; ${report.dataset.casesWithoutManifestFlaws} cases use filename CWE labels; ${report.dataset.overriddenFlawAnchors.length} conflicting flaw anchors overridden by explicit suite polarity.`, '',
    ] : []),
    `Unit: ${report.policy.unit}.`,
    `Matching: ${report.policy.match}.`,
    'All labeled CWEs remain in the denominator. Duplicate findings count once per labeled unit.',
    'Scan: tests included; all severities; low confidence and above; suppressions disabled; OSV disabled.', '',
    ...(report.scan.stats.csharpParser ? [
      `C# parser coverage: ${report.scan.stats.csharpParser.completeFiles}/${report.scan.stats.csharpParser.eligibleFiles} files (${pct(report.scan.stats.csharpParser.fileRatio)}); ${report.scan.stats.csharpParser.completeMethods}/${report.scan.stats.csharpParser.discoveredMethods} methods (${pct(report.scan.stats.csharpParser.methodRatio)}); ${report.scan.stats.csharpParser.fallbackFiles} fallback files.`, '',
    ] : []),
    '| CWE | Cases | TP | FP | TN | FN | Recall | FPR | Precision |',
    '|---|---:|---:|---:|---:|---:|---:|---:|---:|',
    ...report.byCwe.map((x) => row(`CWE-${x.cwe}`, x)), row('Total (micro)', report.totals), '',
    'Recall = TP/(TP+FN); FPR = FP/(FP+TN); precision = TP/(TP+FP). Undefined rates are n/a (JSON null).', '',
    ...report.policy.limitations.map((x) => `- ${x}`), '',
    `Unscored findings: ${JSON.stringify(report.unscoredFindings)}.`, '',
    'These synthetic benchmark measurements do not estimate production application accuracy or human triage quality.', '',
  ].join('\n');
}

async function runLabeled(root, opts, definition) {
  if (opts.revision !== undefined && !/^[a-f0-9]{40}$/i.test(opts.revision)) throw new Error('dataset revision must be a full 40-character Git commit SHA');
  const out = outputDirectory(root, opts.out || definition.defaultOut);
  const listing = walk(root);
  if (listing.truncated) throw new Error('benchmark scan coverage is truncated by file limit');
  const listed = new Set(listing.files.map((f) => f.rel));
  const sources = new Set(definition.labels.flatMap((label) => label.regions.map((r) => r.file)));
  for (const rel of sources) {
    if (!listed.has(rel)) throw new Error(`labeled source skipped by scanner limits: ${rel}`);
    const bytes = readBounded(root, rel);
    if (isProbablyBinary(bytes)) throw new Error(`binary labeled source: ${rel}`);
    const lines = bytes.toString('utf8').split('\n').length;
    for (const region of definition.regionsByFile.get(rel) || []) {
      if (!Number.isInteger(region.startLine) || !Number.isInteger(region.endLine) ||
          region.startLine < 1 || region.endLine < region.startLine || region.endLine > lines) {
        throw new Error(`labeled region outside source: ${rel}:${region.startLine}-${region.endLine}`);
      }
    }
  }
  const inputSha256 = hashInputs(root, definition.inputFiles);
  const sourceSha256 = toolHash();
  const result = await scan(root, { ...SCAN_OPTIONS, name: definition.name });
  if (result.stats.truncated) throw new Error('benchmark scan coverage is truncated');
  if (toolHash() !== sourceSha256 || hashInputs(root, definition.inputFiles) !== inputSha256) throw new Error('benchmark inputs or harness source changed during measurement');
  const report = {
    schema: 'appsec-harness/benchmark@1', measuredAt: new Date().toISOString(),
    tool: { name: pkg.name, version: pkg.version, sourceSha256 },
    runtime: { node: process.version, platform: process.platform, arch: process.arch },
    dataset: { name: definition.name, source: definition.source, version: definition.version || null,
      revision: opts.revision || null, revisionSource: 'user-supplied, not verified',
      inputSha256, expectedSha256: hashInputs(root, definition.manifestFiles), ...definition.metadata },
    policy: { ...definition.policy, excludesUnsupportedCwes: false, cweAliases: false, duplicateDetections: 'one prediction per labeled unit' },
    scan: { options: { ...SCAN_OPTIONS }, stats: result.stats, warnings: result.warnings, durationMs: result.durationMs },
    ...scoreRegions(definition.labels, result.findings),
  };
  fs.mkdirSync(out, { recursive: true });
  writeReportFile(out, 'benchmark.json', JSON.stringify(report, null, 2) + '\n');
  writeReportFile(out, 'benchmark.md', markdown(report));
  return report;
}

function regionIndex(labels) {
  const result = new Map();
  for (const label of labels) for (const region of label.regions) {
    if (!result.has(region.file)) result.set(region.file, []);
    result.get(region.file).push(region);
  }
  return result;
}

module.exports = { datasetRoot, inventory, readBounded, sha256, scoreRegions, markdown, runLabeled, regionIndex };
