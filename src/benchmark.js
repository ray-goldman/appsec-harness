'use strict';
// Independent labels are data. Never build or execute the benchmark application.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { scan } = require('./engine');
const { walk } = require('./walker');
const { isProbablyBinary } = require('./util');
const pkg = require('../package.json');

const TEST_DIR = 'src/main/java/org/owasp/benchmark/testcode';
const SCAN_OPTIONS = Object.freeze({
  includeTests: true, minConfidence: 'low', minSeverity: 'info',
  trustSuppressions: false, osv: false,
});
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const rate = (numerator, denominator) => denominator ? numerator / denominator : null;

function parseExpectedResults(text) {
  const cases = [], seen = new Set();
  const version = text.match(/Benchmark version:\s*([0-9]+(?:\.[0-9]+)*)/)?.[1] || null;
  for (const [index, raw] of text.replace(/^\uFEFF/, '').split(/\r?\n/).entries()) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    // Upstream OWASP Java uses four unquoted fields; do not guess at other CSV dialects.
    const fields = line.split(',').map((x) => x.trim());
    const [id, category, vulnerable, cwe] = fields;
    if (fields.length !== 4 || !/^BenchmarkTest\d{5}$/.test(id) ||
        !/^[a-z][a-z0-9_-]*$/i.test(category) || !/^(true|false)$/.test(vulnerable) ||
        !/^[1-9]\d{0,4}$/.test(cwe)) {
      throw new Error(`invalid OWASP expected-results row ${index + 1}`);
    }
    if (seen.has(id)) throw new Error(`duplicate expected-results case ${id}`);
    seen.add(id);
    cases.push({ id, category, vulnerable: vulnerable === 'true', cwe: Number(cwe), file: `${TEST_DIR}/${id}.java` });
  }
  if (!cases.length) throw new Error('expected-results file contains no cases');
  return { version, cases };
}

function metrics(counts) {
  return {
    ...counts,
    truePositiveRate: rate(counts.tp, counts.tp + counts.fn),
    falsePositiveRate: rate(counts.fp, counts.fp + counts.tn),
    precision: rate(counts.tp, counts.tp + counts.fp),
  };
}

function scoreBenchmark(labels, findings) {
  const byFile = new Map(labels.map((label) => [label.file, { label, matches: [] }]));
  const unscoredFindings = { notOpen: 0, unlabeledFile: 0, wrongCwe: 0 };
  for (const finding of findings) {
    if (finding.status !== 'open') { unscoredFindings.notOpen++; continue; }
    const item = byFile.get(finding.file.replace(/\\/g, '/'));
    if (!item) { unscoredFindings.unlabeledFile++; continue; }
    if (!finding.cwe.includes(item.label.cwe)) { unscoredFindings.wrongCwe++; continue; }
    item.matches.push({ ruleId: finding.ruleId, line: finding.line });
  }
  const counts = () => ({ cases: 0, tp: 0, fp: 0, tn: 0, fn: 0 });
  const total = counts(), groups = new Map(), cases = [];
  for (const { label, matches } of byFile.values()) {
    const prediction = matches.length > 0;
    const outcome = label.vulnerable ? (prediction ? 'tp' : 'fn') : (prediction ? 'fp' : 'tn');
    if (!groups.has(label.cwe)) groups.set(label.cwe, { cwe: label.cwe, ...counts() });
    const group = groups.get(label.cwe);
    total.cases++; total[outcome]++;
    group.cases++; group[outcome]++;
    cases.push({ ...label, prediction, outcome, matches });
  }
  return {
    totals: metrics(total),
    byCwe: [...groups.values()].sort((a, b) => a.cwe - b.cwe).map(metrics),
    unscoredFindings, cases,
  };
}

function inside(root, target) {
  const rel = path.relative(root, target);
  return !path.isAbsolute(rel) && rel !== '..' && !rel.startsWith('..' + path.sep);
}

function checkedFile(root, rel) {
  if (!rel || path.isAbsolute(rel) || /[:\0]/.test(rel) ||
      rel.split(/[\\/]/).some((part) => !part || part === '..' || part === '.')) {
    throw new Error('input paths must be relative and stay inside the dataset');
  }
  let file = root;
  const parts = rel.split(/[\\/]/);
  for (let i = 0; i < parts.length; i++) {
    file = path.join(file, parts[i]);
    let stat;
    try { stat = fs.lstatSync(file); } catch (e) {
      throw new Error(`missing or unreadable input/case ${rel} (${e.code})`);
    }
    if (stat.isSymbolicLink()) throw new Error(`refusing linked input/case ${rel}`);
    if (i === parts.length - 1 ? !stat.isFile() : !stat.isDirectory()) {
      throw new Error(`invalid input/case type: ${rel}`);
    }
  }
  return file;
}

// Resolve existing ancestors before testing containment, including Windows junctions.
function outputDirectory(root, requested) {
  let ancestor = path.resolve(requested);
  const tail = [];
  while (!fs.existsSync(ancestor)) {
    const parent = path.dirname(ancestor);
    if (parent === ancestor) throw new Error('cannot resolve output directory');
    tail.unshift(path.basename(ancestor)); ancestor = parent;
  }
  const out = path.join(fs.realpathSync(ancestor), ...tail);
  if (inside(root, out)) throw new Error('benchmark output must be outside the dataset');
  return out;
}

function hashInputs(root, files) {
  const hash = crypto.createHash('sha256');
  for (const rel of [...files].sort()) {
    const bytes = fs.readFileSync(checkedFile(root, rel));
    hash.update(rel + '\0' + bytes.length + '\0');
    hash.update(bytes);
  }
  return hash.digest('hex');
}

function toolHash() {
  const root = path.join(__dirname, '..');
  const files = ['package.json'];
  for (const dir of ['bin', 'src']) {
    const listing = walk(path.join(root, dir));
    files.push(...listing.files.map((file) => `${dir}/${file.rel}`));
  }
  return hashInputs(root, files);
}

function toMarkdown(report) {
  const pct = (value) => value === null ? 'n/a' : `${(value * 100).toFixed(2)}%`;
  const row = (name, x) => `| ${name} | ${x.cases} | ${x.tp} | ${x.fp} | ${x.tn} | ${x.fn} | ${pct(x.truePositiveRate)} | ${pct(x.falsePositiveRate)} | ${pct(x.precision)} |`;
  return [
    '# OWASP Benchmark Java measurement', '',
    `Measured at: ${report.measuredAt}`,
    `Dataset version: ${report.dataset.version || 'unspecified'}`,
    `Declared dataset revision: ${report.dataset.revision || 'not supplied'} (not verified by the runner)`,
    `Input SHA-256: \`${report.dataset.inputSha256}\``,
    `Expected-results SHA-256: \`${report.dataset.expectedSha256}\``,
    `Harness source SHA-256: \`${report.tool.sourceSha256}\``,
    `Harness: ${report.tool.version}; Node: ${report.runtime.node}; platform: ${report.runtime.platform}`, '',
    'Unit: one labeled servlet. A detection requires the exact case file and expected CWE. All labeled cases, including unsupported CWEs, are counted. Duplicate findings count once.',
    'Scan settings: include test paths; all severities; confidence low and above; inline suppressions disabled; OSV disabled.', '',
    '| CWE | Cases | TP | FP | TN | FN | TPR / recall | FPR | Precision |',
    '|---|---:|---:|---:|---:|---:|---:|---:|---:|',
    ...report.byCwe.map((x) => row(`CWE-${x.cwe}`, x)),
    row('Total (micro)', report.totals), '',
    'TPR = TP / (TP + FN). FPR = FP / (FP + TN). Precision = TP / (TP + FP). An undefined rate is n/a.',
    `Unscored findings: ${report.unscoredFindings.unlabeledFile} outside labeled files; ${report.unscoredFindings.wrongCwe} with a different CWE; ${report.unscoredFindings.notOpen} not open.`, '',
    'This measures independently labeled synthetic Java cases. It does not measure production application accuracy, cross-file recall, triage decisions, or the internal regression corpus. This is the harness evaluator, not an OWASP-certified scorecard.', '',
  ].join('\n');
}

function writeReportFile(out, name, text) {
  const destination = path.join(out, name);
  if (fs.existsSync(destination) && !fs.lstatSync(destination).isFile()) {
    throw new Error(`refusing non-regular report destination ${name}`);
  }
  const temporary = path.join(out, `.${name}-${crypto.randomBytes(8).toString('hex')}.tmp`);
  try {
    fs.writeFileSync(temporary, text, { flag: 'wx' });
    // Replace rather than truncate an existing inode (which could be hard-linked).
    fs.renameSync(temporary, destination);
  } finally {
    if (fs.existsSync(temporary)) fs.unlinkSync(temporary);
  }
}

async function runBenchmark(directory, opts = {}) {
  if (!directory || typeof directory !== 'string') throw new Error('benchmark dataset directory required');
  if (opts.revision !== undefined && !/^[a-f0-9]{40}$/i.test(opts.revision)) {
    throw new Error('dataset revision must be a full 40-character Git commit SHA');
  }
  const root = fs.realpathSync(path.resolve(directory));
  if (!fs.statSync(root).isDirectory()) throw new Error('benchmark input must be a directory');
  const out = outputDirectory(root, opts.out || 'appsec-reports/benchmarks/owasp-java');
  const expectedRel = opts.expected || 'expectedresults-1.2.csv';
  const expectedFile = checkedFile(root, expectedRel);
  if (fs.statSync(expectedFile).size > 5 * 1024 * 1024) throw new Error('expected-results file exceeds 5 MiB');
  const expectedBytes = fs.readFileSync(expectedFile);
  const { version, cases } = parseExpectedResults(expectedBytes.toString('utf8'));
  const listing = walk(root);
  if (listing.truncated) throw new Error('benchmark scan coverage is truncated by the file limit');
  const listed = new Set(listing.files.map((file) => file.rel));
  for (const label of cases) {
    const file = checkedFile(root, label.file);
    if (!listed.has(label.file)) throw new Error(`case skipped by scanner limits: ${label.id}`);
    if (isProbablyBinary(fs.readFileSync(file))) throw new Error(`binary case cannot be scanned: ${label.id}`);
  }
  const inputSha256 = hashInputs(root, [...listed]);
  const result = await scan(root, { ...SCAN_OPTIONS, name: 'OWASP Benchmark Java' });
  if (result.stats.truncated) throw new Error('benchmark scan coverage is truncated');
  const report = {
    schema: 'appsec-harness/benchmark@1',
    measuredAt: new Date().toISOString(),
    tool: { name: pkg.name, version: pkg.version, sourceSha256: toolHash() },
    runtime: { node: process.version, platform: process.platform, arch: process.arch },
    dataset: {
      name: 'OWASP Benchmark Java', source: 'https://github.com/OWASP-Benchmark/BenchmarkJava',
      version, revision: opts.revision || null, revisionSource: 'user-supplied, not verified',
      expectedSha256: sha256(expectedBytes), inputSha256,
    },
    policy: {
      id: 'owasp-java-file-cwe@1', unit: 'labeled servlet',
      match: 'exact source path and expected CWE in finding.cwe; status=open',
      duplicateDetections: 'one positive prediction per case',
      cweAliases: false, excludesUnsupportedCwes: false,
    },
    scan: { options: { ...SCAN_OPTIONS }, stats: result.stats, warnings: result.warnings, durationMs: result.durationMs },
    ...scoreBenchmark(cases, result.findings),
  };
  fs.mkdirSync(out, { recursive: true });
  writeReportFile(out, 'benchmark.json', JSON.stringify(report, null, 2) + '\n');
  writeReportFile(out, 'benchmark.md', toMarkdown(report));
  return report;
}

module.exports = {
  parseExpectedResults, scoreBenchmark, runBenchmark, toMarkdown,
  // Shared by the external-label adapters; keep input/output safety consistent.
  checkedFile, outputDirectory, hashInputs, toolHash, writeReportFile, SCAN_OPTIONS, metrics,
};
