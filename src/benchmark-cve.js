'use strict';
// Upstream source is untrusted data. Only explicit fetch downloads; measurement is offline.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { scan } = require('./engine');
const { walk } = require('./walker');
const { isProbablyBinary } = require('./util');
const {
  checkedFile, outputDirectory, hashInputs, toolHash, writeReportFile, SCAN_OPTIONS, metrics,
} = require('./benchmark');
const pkg = require('../package.json');

const DEFAULT_MANIFEST = path.join(__dirname, '../benchmarks/cve-fixes.json');
const MAX_FILE = 1024 * 1024;
const MAX_TOTAL = 64 * MAX_FILE;
const OPTIONS = Object.freeze({ ...SCAN_OPTIONS, includeVendored: true });
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const counts = () => ({ cases: 0, tp: 0, fp: 0, tn: 0, fn: 0 });

function sourcePath(value) {
  if (typeof value !== 'string' || value.length > 240 ||
      !/^[A-Za-z0-9_/-][A-Za-z0-9_.\/-]*\.(?:js|mjs|cjs|ts|tsx|jsx|py|php|java|kt|go|rb|cs)$/.test(value) ||
      value.startsWith('/') || value.split('/').length > 30 ||
      value.split('/').some((part) => !part || part.startsWith('.') || /[. ]$/.test(part) ||
        /^(?:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/i.test(part))) {
    throw new Error('invalid or unsafe corpus source path');
  }
}

function httpsReference(value) {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !url.username && !url.password && !url.port;
  } catch { return false; }
}

// Walk all ancestors explicitly: mkdir({recursive:true}) alone follows linked ancestors.
function safeDirectory(directory, create = false) {
  const absolute = path.resolve(directory);
  const base = path.parse(absolute).root;
  if (base.startsWith('\\\\')) throw new Error('UNC corpus paths are not supported');
  let current = base;
  for (const part of absolute.slice(base.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    let stat;
    try { stat = fs.lstatSync(current); } catch (error) {
      if (!create || error.code !== 'ENOENT') throw error;
      fs.mkdirSync(current);
      stat = fs.lstatSync(current);
    }
    if (stat.isSymbolicLink() || !stat.isDirectory()) {
      throw new Error('corpus directories must be real directories, not links');
    }
  }
  return absolute;
}

function readManifest(filename = DEFAULT_MANIFEST) {
  if (typeof filename !== 'string') throw new Error('manifest path must be a string');
  const absolute = path.resolve(filename);
  const directory = safeDirectory(path.dirname(absolute));
  const file = checkedFile(directory, path.basename(absolute));
  if (fs.statSync(file).size > MAX_FILE) throw new Error('corpus manifest exceeds 1 MiB');
  const bytes = fs.readFileSync(file);
  let manifest;
  try { manifest = JSON.parse(bytes.toString('utf8')); } catch { throw new Error('invalid corpus manifest JSON'); }
  if (!manifest || manifest.schema !== 'appsec-harness/cve-fixes@1' ||
      typeof manifest.version !== 'string' || !/^[0-9]+\.[0-9]+\.[0-9]+$/.test(manifest.version) ||
      !Array.isArray(manifest.entries) || !manifest.entries.length || manifest.entries.length > 128) {
    throw new Error('invalid CVE corpus manifest schema, version, or entry count');
  }
  const ids = new Set();
  let totalBytes = 0, totalFiles = 0;
  for (const entry of manifest.entries) {
    if (!entry || !/^CVE-\d{4}-\d{4,8}$/.test(entry.id) || ids.has(entry.id) ||
        !Number.isInteger(entry.cwe) || entry.cwe < 1 || entry.cwe > 99999 ||
        !/^[A-Za-z0-9_-][A-Za-z0-9_.-]*\/[A-Za-z0-9_-][A-Za-z0-9_.-]*$/.test(entry.repository) ||
        entry.repository.length > 200 || !/^[A-Za-z+# -]{1,40}$/.test(entry.language) ||
        !Array.isArray(entry.advisoryUrls) || !entry.advisoryUrls.length ||
        entry.advisoryUrls.length > 16 || !entry.advisoryUrls.every(httpsReference) ||
        !entry.license || typeof entry.license.spdx !== 'string' || !httpsReference(entry.license.url) ||
        typeof entry.evidence !== 'string' || entry.evidence.length < 40 || entry.evidence.length > 8000 ||
        typeof entry.scope !== 'string' || entry.scope.length < 40 || entry.scope.length > 8000) {
      throw new Error('invalid or duplicate CVE corpus entry');
    }
    ids.add(entry.id);
    for (const variant of ['parent', 'fix']) {
      const snapshot = entry[variant];
      if (!snapshot || !/^[a-f0-9]{40}$/.test(snapshot.revision) ||
          !Array.isArray(snapshot.files) || !snapshot.files.length || snapshot.files.length > 64) {
        throw new Error(`invalid snapshot in ${entry.id}`);
      }
      const paths = new Set();
      for (const source of snapshot.files) {
        if (!source || typeof source !== 'object') throw new Error('invalid source entry');
        sourcePath(source.path);
        // Case-insensitive uniqueness makes the manifest portable to Windows/macOS.
        if (paths.has(source.path.toLowerCase()) || !/^[a-f0-9]{64}$/.test(source.sha256) ||
            !Number.isInteger(source.bytes) || source.bytes < 1 || source.bytes > MAX_FILE) {
          throw new Error(`invalid hash, size, or duplicate source in ${entry.id}`);
        }
        paths.add(source.path.toLowerCase());
        totalBytes += source.bytes; totalFiles++;
      }
    }
    if (entry.parent.revision === entry.fix.revision ||
        entry.fixUrl !== `https://github.com/${entry.repository}/commit/${entry.fix.revision}` ||
        entry.parentVerification?.firstParent !== entry.parent.revision ||
        entry.parentVerification?.apiUrl !== `https://api.github.com/repos/${entry.repository}/commits/${entry.fix.revision}` ||
        !Number.isFinite(Date.parse(entry.parentVerification?.checkedAt)) ||
        JSON.stringify(entry.parent.files.map((file) => file.path).sort()) !==
          JSON.stringify(entry.fix.files.map((file) => file.path).sort())) {
      throw new Error(`invalid parent/fix provenance or differing source paths in ${entry.id}`);
    }
    if (!entry.parent.files.some((before) => entry.fix.files.find((after) => after.path === before.path).sha256 !== before.sha256)) {
      throw new Error(`parent and fix bytes are identical in ${entry.id}`);
    }
  }
  if (totalBytes > MAX_TOTAL || totalFiles > 2048) throw new Error('corpus exceeds byte/file limits');
  return { manifest, bytes };
}

function relativeSource(entry, variant, source) {
  return `${entry.id}/${variant}/${source.path}`;
}

function verifySource(root, relative, source) {
  const file = checkedFile(root, relative);
  if (fs.statSync(file).size !== source.bytes) throw new Error(`source size mismatch: ${relative}`);
  const bytes = fs.readFileSync(file);
  if (bytes.length !== source.bytes || sha256(bytes) !== source.sha256) {
    throw new Error(`source SHA-256 mismatch: ${relative}`);
  }
  if (isProbablyBinary(bytes)) throw new Error(`binary corpus source: ${relative}`);
}

function expectedInputs(manifest) {
  return manifest.entries.flatMap((entry) => ['parent', 'fix'].flatMap((variant) =>
    entry[variant].files.map((source) => ({ relative: relativeSource(entry, variant, source), source }))));
}

function verifyDataset(root, manifest) {
  const inputs = expectedInputs(manifest);
  const expected = new Set(inputs.map((item) => item.relative));
  const directories = new Set();
  for (const relative of expected) {
    const parts = relative.split('/');
    for (let i = 1; i < parts.length; i++) directories.add(parts.slice(0, i).join('/'));
  }
  // Inspect even files that the scanner would skip. Extra bytes may alter project heuristics.
  const visit = (directory, prefix = '') => {
    for (const item of fs.readdirSync(directory, { withFileTypes: true })) {
      const relative = prefix + item.name;
      if (item.isSymbolicLink()) throw new Error(`linked corpus input: ${relative}`);
      if (item.isDirectory() && directories.has(relative)) visit(path.join(directory, item.name), relative + '/');
      else if (!item.isFile() || !expected.has(relative)) throw new Error(`unlisted corpus input: ${relative}`);
    }
  };
  visit(root);
  for (const { relative, source } of inputs) verifySource(root, relative, source);
  return inputs.map((item) => item.relative);
}

async function download(url, expectedBytes) {
  // URLs are constructed solely from validated repo, immutable revision and source path.
  const parsed = new URL(url);
  if (parsed.origin !== 'https://raw.githubusercontent.com' || parsed.search || parsed.hash) {
    throw new Error('corpus fetch allows only pinned raw.githubusercontent.com source URLs');
  }
  const response = await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(30000) });
  if (!response.ok || !response.body) throw new Error(`corpus download failed: HTTP ${response.status}`);
  const length = response.headers.get('content-length');
  if (length && (!/^\d+$/.test(length) || Number(length) > MAX_FILE)) {
    await response.body.cancel();
    throw new Error('corpus download exceeds size limit');
  }
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > expectedBytes || size > MAX_FILE) throw new Error('corpus download exceeds pinned size');
      chunks.push(Buffer.from(value));
    }
  } finally {
    await reader.cancel();
  }
  if (size !== expectedBytes) throw new Error('corpus download differs from pinned size');
  return Buffer.concat(chunks, size);
}

async function fetchCveCorpus(directory, opts = {}) {
  if (typeof directory !== 'string' || !directory) throw new Error('CVE corpus directory required');
  const { manifest, bytes: manifestBytes } = readManifest(opts.manifest);
  const root = safeDirectory(directory, true);
  let downloaded = 0, reused = 0;
  for (const entry of manifest.entries) {
    for (const variant of ['parent', 'fix']) {
      for (const source of entry[variant].files) {
        const relative = relativeSource(entry, variant, source);
        const destination = path.join(root, ...relative.split('/'));
        safeDirectory(path.dirname(destination), true);
        try {
          fs.lstatSync(destination);
          verifySource(root, relative, source);
          reused++;
          continue;
        } catch (error) {
          // Never overwrite a mismatched, linked, or unreadable existing file.
          if (error.code !== 'ENOENT') throw error;
        }
        const url = `https://raw.githubusercontent.com/${entry.repository}/${entry[variant].revision}/${source.path}`;
        const bytes = await download(url, source.bytes);
        if (sha256(bytes) !== source.sha256 || isProbablyBinary(bytes)) {
          throw new Error(`download SHA-256 mismatch or binary source: ${relative}`);
        }
        safeDirectory(path.dirname(destination));
        // Exclusive creation never truncates existing files or follows a pre-existing symlink.
        const fd = fs.openSync(destination, 'wx', 0o600);
        try { fs.writeFileSync(fd, bytes); } finally { fs.closeSync(fd); }
        verifySource(root, relative, source);
        downloaded++;
      }
    }
  }
  const files = verifyDataset(root, manifest);
  return {
    schema: 'appsec-harness/cve-fetch@1', directory: root, entries: manifest.entries.length,
    files: files.length, downloaded, reused, manifestSha256: sha256(manifestBytes),
    inputSha256: hashInputs(root, files),
  };
}

function toMarkdown(report) {
  const pct = (value) => value === null ? 'n/a' : `${(value * 100).toFixed(2)}%`;
  const row = (name, item) => `| ${name} | ${item.cases} | ${item.tp} | ${item.fp} | ${item.tn} | ${item.fn} | ${pct(item.truePositiveRate)} | ${pct(item.falsePositiveRate)} | ${pct(item.precision)} |`;
  return [
    '# Real CVE fix-pair measurement', '',
    `Measured at: ${report.measuredAt}`,
    `Corpus version: ${report.dataset.version}; pairs: ${report.pairs.total}`,
    `Manifest SHA-256: \`${report.dataset.manifestSha256}\``,
    `Input SHA-256: \`${report.dataset.inputSha256}\``,
    `Harness source SHA-256: \`${report.tool.sourceSha256}\``,
    `Harness: ${report.tool.version}; Node: ${report.runtime.node}; platform: ${report.runtime.platform}`, '',
    'Unit: one CVE revision snapshot. Parent is positive; fix is negative. A hit is an open finding with the exact expected CWE in any listed affected source file. Duplicate findings count once. All entries and unsupported CWEs remain in the denominator.',
    'Snapshots contain full original affected files with limited repository context. Fixed-side FP/TN means changed-file CWE presence/silence, not verified CVE localization or application-wide safety. Unrelated findings of the same CWE in these files can count as hits; an FP here is a benchmark outcome, not a proven false vulnerability report.', '',
    'Scan settings: all severities; confidence low and above; test paths and vendored source included; inline suppressions disabled; OSV disabled. Target code is never executed.', '',
    '| CWE | Snapshots | TP | FP | TN | FN | TPR / recall | FPR | Precision |',
    '|---|---:|---:|---:|---:|---:|---:|---:|---:|',
    ...report.byCwe.map((item) => row(`CWE-${item.cwe}`, item)),
    row('Total (micro)', report.totals), '',
    `Successful complete pairs (parent hit AND fix silent): ${report.pairs.successful}/${report.pairs.total} (${pct(report.pairs.rate)}).`, '',
    '| CVE | CWE | Parent | Fix | Successful pair |',
    '|---|---|---|---|---|',
    ...report.cases.map((item) => `| ${item.id} | CWE-${item.cwe} | ${item.parent.outcome.toUpperCase()} | ${item.fix.outcome.toUpperCase()} | ${item.successfulPair ? 'yes' : 'no'} |`), '',
    'TPR = TP / (TP + FN). FPR = FP / (FP + TN). Precision = TP / (TP + FP). Undefined rates are n/a.',
    'The corpus is small, curated, and deliberately includes unsupported weakness classes. It is not a representative estimate of production accuracy. Advisory labels and first-parent relationships were curated from upstream evidence; offline runs verify pinned bytes, not the truth of third-party advisories.',
    'Per-case immutable revisions, source hashes, matching rule IDs/locations, provenance, scope, and scanner statistics are in benchmark.json.', '',
  ].join('\n');
}

async function runCveBenchmark(directory, opts = {}) {
  if (typeof directory !== 'string' || !directory) throw new Error('CVE corpus directory required');
  const { manifest, bytes: manifestBytes } = readManifest(opts.manifest);
  const root = safeDirectory(directory);
  const out = outputDirectory(root, opts.out || 'appsec-reports/benchmarks/cve-fixes');
  // Also reject output ancestors of the dataset, which could otherwise mix reports and inputs.
  const toRoot = path.relative(out, root);
  if (!path.isAbsolute(toRoot) && toRoot !== '..' && !toRoot.startsWith('..' + path.sep)) {
    throw new Error('benchmark output must not contain the dataset');
  }
  const files = verifyDataset(root, manifest);
  const inputSha256 = hashInputs(root, files);
  const sourceSha256 = toolHash();
  const total = counts(), groups = new Map(), cases = [];
  const unscoredFindings = { notOpen: 0, unlabeledFile: 0, wrongCwe: 0 };
  for (const entry of manifest.entries) {
    if (!groups.has(entry.cwe)) groups.set(entry.cwe, { cwe: entry.cwe, ...counts() });
    const item = { ...entry };
    for (const variant of ['parent', 'fix']) {
      const snapshot = entry[variant];
      const snapshotRoot = path.join(root, entry.id, variant);
      safeDirectory(snapshotRoot);
      const listed = walk(snapshotRoot, OPTIONS);
      const expected = new Set(snapshot.files.map((source) => source.path));
      if (listed.truncated || listed.files.length !== expected.size ||
          listed.files.some((file) => !expected.has(file.rel))) {
        throw new Error(`scanner skips or truncates corpus source: ${entry.id}/${variant}`);
      }
      const result = await scan(snapshotRoot, { ...OPTIONS, name: `${entry.id} ${variant}` });
      if (result.stats.truncated || result.stats.files !== expected.size) {
        throw new Error(`incomplete corpus scan: ${entry.id}/${variant}`);
      }
      const matches = [];
      for (const finding of result.findings) {
        if (finding.status !== 'open') { unscoredFindings.notOpen++; continue; }
        if (!expected.has(finding.file.replace(/\\/g, '/'))) { unscoredFindings.unlabeledFile++; continue; }
        if (!finding.cwe.includes(entry.cwe)) { unscoredFindings.wrongCwe++; continue; }
        matches.push({ ruleId: finding.ruleId, file: finding.file.replace(/\\/g, '/'), line: finding.line });
      }
      const prediction = matches.length > 0;
      const outcome = variant === 'parent' ? (prediction ? 'tp' : 'fn') : (prediction ? 'fp' : 'tn');
      total.cases++; total[outcome]++;
      const group = groups.get(entry.cwe);
      group.cases++; group[outcome]++;
      item[variant] = {
        ...snapshot, prediction, outcome, matches,
        scan: { stats: result.stats, warnings: result.warnings, durationMs: result.durationMs },
      };
    }
    item.successfulPair = item.parent.outcome === 'tp' && item.fix.outcome === 'tn';
    cases.push(item);
  }
  verifyDataset(root, manifest);
  if (inputSha256 !== hashInputs(root, files) || sourceSha256 !== toolHash()) {
    throw new Error('corpus or harness changed during measurement');
  }
  const successful = cases.filter((item) => item.successfulPair).length;
  const report = {
    schema: 'appsec-harness/cve-benchmark@1', measuredAt: new Date().toISOString(),
    tool: { name: pkg.name, version: pkg.version, sourceSha256 },
    runtime: { node: process.version, platform: process.platform, arch: process.arch },
    dataset: { name: 'Real upstream CVE fix pairs', version: manifest.version, manifestSha256: sha256(manifestBytes), inputSha256, files: files.length },
    policy: {
      id: 'cve-changed-file-cwe@1', unit: 'one CVE revision snapshot',
      match: 'open finding in a listed affected file with exact expected CWE; duplicates count once',
      parentLabel: 'positive', fixLabel: 'negative for the cited CWE in selected affected files only',
      cweAliases: false, excludesUnsupportedCwes: false,
      context: 'full selected source files, limited repository context; not CVE localization or application-wide safety',
      provenance: 'first parent verified during curation; immutable source bytes verified offline on every run',
    },
    scan: { options: { ...OPTIONS } },
    totals: metrics(total), byCwe: [...groups.values()].sort((a, b) => a.cwe - b.cwe).map(metrics),
    pairs: { total: cases.length, successful, rate: successful / cases.length },
    unscoredFindings, cases,
  };
  safeDirectory(out, true);
  writeReportFile(out, 'benchmark.json', JSON.stringify(report, null, 2) + '\n');
  writeReportFile(out, 'benchmark.md', toMarkdown(report));
  return report;
}

module.exports = { fetchCveCorpus, runCveBenchmark, toMarkdown };
