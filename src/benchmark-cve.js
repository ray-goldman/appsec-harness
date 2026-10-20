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
const DEFAULT_LOCALIZATION = path.join(__dirname, '../benchmarks/cve-localization.json');
const MAX_FILE = 1024 * 1024;
const MAX_TOTAL = 64 * MAX_FILE;
const OPTIONS = Object.freeze({ ...SCAN_OPTIONS, includeVendored: true });
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const counts = () => ({ cases: 0, tp: 0, fp: 0, tn: 0, fn: 0 });

// Separate versioned labels: never rewrite the historical file+CWE policy.
function readLocalization(filename, manifest, manifestBytes, root) {
  const explicit = filename !== undefined;
  if (explicit && (typeof filename !== 'string' || !filename)) throw new Error('localization path must be a string');
  const absolute = path.resolve(filename || DEFAULT_LOCALIZATION);
  const directory = safeDirectory(path.dirname(absolute));
  const file = checkedFile(directory, path.basename(absolute));
  if (fs.statSync(file).size > MAX_FILE) throw new Error('localization exceeds 1 MiB');
  const bytes = fs.readFileSync(file);
  let metadata;
  try { metadata = JSON.parse(bytes.toString('utf8')); } catch { throw new Error('invalid localization JSON'); }
  if (!metadata || metadata.schema !== 'appsec-harness/cve-localization@1' ||
      !/^\d+\.\d+\.\d+$/.test(metadata.version) || !/^[a-f0-9]{64}$/.test(metadata.manifestSha256) ||
      !Array.isArray(metadata.entries) || !metadata.entries.length || metadata.entries.length > 128) {
    throw new Error('invalid localization schema');
  }
  if (metadata.manifestSha256 !== sha256(manifestBytes)) {
    if (explicit) throw new Error('localization manifest provenance mismatch');
    return { status: 'unavailable', reason: 'Bundled localization does not match these exact manifest bytes; supply --localization with reviewed matching metadata.' };
  }
  const byId = new Map(manifest.entries.map((entry) => [entry.id, entry]));
  const seen = new Set();
  const prose = (value) => typeof value === 'string' && value.length >= 12 && value.length <= 8000;
  for (const entry of metadata.entries) {
    const original = byId.get(entry?.id);
    if (!original || seen.has(entry.id) || entry.cwe !== original.cwe ||
        !prose(entry.rationale) || !prose(entry.missingContext) ||
        !Array.isArray(entry.permitted) || !entry.permitted.length || entry.permitted.length > 32) {
      throw new Error('invalid, duplicate, or incomplete localization entry');
    }
    seen.add(entry.id);
    const rules = new Set();
    for (const criterion of entry.permitted) {
      if (!criterion || typeof criterion.ruleId !== 'string' ||
          !/^(?:\*|[A-Z][A-Z0-9-]{1,99})$/.test(criterion.ruleId) ||
          criterion.cwe !== entry.cwe || typeof criterion.requireTaint !== 'boolean' ||
          rules.has(criterion.ruleId)) throw new Error('invalid or duplicate localization rule/CWE criterion');
      rules.add(criterion.ruleId);
    }
    if (rules.has('*') && rules.size > 1) throw new Error('overlapping localization rule criteria');
    for (const variant of ['parent', 'fix']) {
      const snapshot = entry[variant];
      if (!snapshot || snapshot.revision !== original[variant].revision ||
          !Array.isArray(snapshot.regions) || !snapshot.regions.length || snapshot.regions.length > 128) {
        throw new Error('invalid localization snapshot provenance or regions');
      }
      const ranges = new Map();
      for (const region of snapshot.regions) {
        sourcePath(region?.file);
        const source = original[variant].files.find((item) => item.path === region.file);
        if (!source || !Number.isSafeInteger(region.start) || !Number.isSafeInteger(region.end) ||
            region.start < 1 || region.end < region.start || !prose(region.evidence) ||
            !Array.isArray(region.anchors) || !region.anchors.length || region.anchors.length > 16 ||
            region.anchors.some((value) => typeof value !== 'string' || !value.trim() || value.length > 1000) ||
            new Set(region.anchors).size !== region.anchors.length) {
          throw new Error('invalid localization source region or evidence');
        }
        const prior = ranges.get(region.file) || [];
        if (prior.some((item) => region.start <= item.end && item.start <= region.end)) {
          throw new Error('overlapping or duplicate localization regions');
        }
        prior.push(region); ranges.set(region.file, prior);
        const relative = relativeSource(original, variant, source);
        verifySource(root, relative, source);
        const text = fs.readFileSync(checkedFile(root, relative), 'utf8');
        const lines = text.split(/\r?\n/);
        if (lines.at(-1) === '') lines.pop();
        const regionText = lines.slice(region.start - 1, region.end).join('\n');
        if (region.end > lines.length || !region.anchors.every((anchor) => regionText.includes(anchor))) {
          throw new Error(`localization bounds or evidence mismatch: ${entry.id}/${variant}/${region.file}`);
        }
      }
    }
  }
  if (seen.size !== byId.size) throw new Error('incomplete localization CVE coverage');
  return { status: 'available', version: metadata.version, sha256: sha256(bytes), manifestSha256: metadata.manifestSha256, entries: metadata.entries };
}

function scoreLocalized(entries, observations) {
  const observed = new Map(observations.map((item) => [item.id, item]));
  if (observed.size !== observations.length || observed.size !== entries.length ||
      new Set(entries.map((item) => item.id)).size !== entries.length) throw new Error('invalid localization observation coverage');
  const total = counts(), groups = new Map(), cases = [];
  const warnings = { total: 0, matched: 0, notOpen: 0, review: 0, outsideRegion: 0, unapprovedRuleCwe: 0, missingEvidence: 0 };
  for (const entry of entries) {
    const observedCase = observed.get(entry.id);
    if (!observedCase || !Array.isArray(observedCase.parent) || !Array.isArray(observedCase.fix)) {
      throw new Error(`missing localization observations: ${entry.id}`);
    }
    if (!groups.has(entry.cwe)) groups.set(entry.cwe, { cwe: entry.cwe, ...counts() });
    const item = { ...entry };
    for (const variant of ['parent', 'fix']) {
      const matches = [], excluded = [];
      for (const finding of observedCase[variant]) {
        warnings.total++;
        const file = typeof finding.file === 'string' ? finding.file.replace(/\\/g, '/') : '';
        let reason;
        if (finding.status !== 'open') reason = 'notOpen';
        else if (finding.kind !== undefined && finding.kind !== 'vulnerability') reason = 'review';
        else if (!Number.isSafeInteger(finding.line) || !entry[variant].regions.some((region) =>
          region.file === file && finding.line >= region.start && finding.line <= region.end)) reason = 'outsideRegion';
        else {
          const criteria = entry.permitted.filter((criterion) =>
            (criterion.ruleId === '*' || criterion.ruleId === finding.ruleId) &&
            Array.isArray(finding.cwe) && finding.cwe.includes(criterion.cwe));
          if (!criteria.length) reason = 'unapprovedRuleCwe';
          else if (!criteria.some((criterion) => !criterion.requireTaint ||
            (typeof finding.taint?.source === 'string' && finding.taint.source.trim() &&
             Number.isSafeInteger(finding.taint.line) && finding.taint.line > 0))) reason = 'missingEvidence';
        }
        const location = { ruleId: finding.ruleId, file, line: finding.line, kind: finding.kind || 'vulnerability' };
        if (reason) { warnings[reason]++; excluded.push({ ...location, reason }); }
        else { warnings.matched++; matches.push(location); }
      }
      const prediction = matches.length > 0;
      const outcome = variant === 'parent' ? (prediction ? 'tp' : 'fn') : (prediction ? 'fp' : 'tn');
      total.cases++; total[outcome]++;
      const group = groups.get(entry.cwe); group.cases++; group[outcome]++;
      item[variant] = { ...entry[variant], prediction, outcome, matches, excluded };
    }
    item.successfulPair = item.parent.outcome === 'tp' && item.fix.outcome === 'tn';
    cases.push(item);
  }
  const successful = cases.filter((item) => item.successfulPair).length;
  return {
    totals: metrics(total), byCwe: [...groups.values()].sort((a, b) => a.cwe - b.cwe).map(metrics),
    pairs: { total: cases.length, successful, rate: cases.length ? successful / cases.length : null },
    warnings, cases,
  };
}

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
  const localized = report.localized?.status === 'available' ? [
    '## Fix-specific source-region scoring', '',
    `Independent policy: \`${report.localized.policy.id}\`; annotation version: ${report.localized.version}.`,
    `Annotation SHA-256: \`${report.localized.sha256}\``, '',
    'A localized hit requires an open vulnerability finding at a reviewed source region, the exact advisory CWE, and its permitted rule/evidence criteria. Review-only and unrelated warnings are reported separately. Missing finding kind defaults to vulnerability for compatibility. All CVEs remain in the denominator; fixed-side silence alone does not establish detector support or application safety.', '',
    '| CWE | Snapshots | TP | FP | TN | FN | TPR / recall | FPR | Precision |',
    '|---|---:|---:|---:|---:|---:|---:|---:|---:|',
    ...report.localized.byCwe.map((item) => row(`CWE-${item.cwe}`, item)),
    row('Localized total (micro)', report.localized.totals), '',
    `Localized successful complete pairs: ${report.localized.pairs.successful}/${report.localized.pairs.total} (${pct(report.localized.pairs.rate)}).`,
    `Finding counts: ${Object.entries(report.localized.warnings).map(([key, value]) => `${key}=${value}`).join('; ')}.`, '',
    '| CVE | CWE | Parent | Fix | Successful pair |',
    '|---|---|---|---|---|',
    ...report.localized.cases.map((item) => `| ${item.id} | CWE-${item.cwe} | ${item.parent.outcome.toUpperCase()} | ${item.fix.outcome.toUpperCase()} | ${item.successfulPair ? 'yes' : 'no'} |`), '',
    'These scores use a different policy from the historical table above; differences between the two tables are not scanner improvements. Regions, evidence, permitted criteria, excluded finding locations, and missing repository context are recorded in benchmark.json.', '',
  ] : ['## Fix-specific source-region scoring', '', `Unavailable: ${report.localized?.reason || 'this report predates localization metadata'}`, 'Historical baseline results above are unchanged.', ''];
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
    ...localized,
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
  const localization = readLocalization(opts.localization, manifest, manifestBytes, root);
  const inputSha256 = hashInputs(root, files);
  const sourceSha256 = toolHash();
  const total = counts(), groups = new Map(), cases = [], observations = [];
  const unscoredFindings = { notOpen: 0, unlabeledFile: 0, wrongCwe: 0 };
  for (const entry of manifest.entries) {
    if (!groups.has(entry.cwe)) groups.set(entry.cwe, { cwe: entry.cwe, ...counts() });
    const item = { ...entry };
    const observation = { id: entry.id };
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
      observation[variant] = result.findings;
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
    observations.push(observation);
  }
  verifyDataset(root, manifest);
  if (inputSha256 !== hashInputs(root, files) || sourceSha256 !== toolHash()) {
    throw new Error('corpus or harness changed during measurement');
  }
  const successful = cases.filter((item) => item.successfulPair).length;
  if (localization.status === 'available' &&
      readLocalization(opts.localization, manifest, manifestBytes, root).sha256 !== localization.sha256) {
    throw new Error('localization changed during measurement');
  }
  const localized = localization.status === 'available' ? {
    status: 'available', version: localization.version, sha256: localization.sha256,
    manifestSha256: localization.manifestSha256,
    policy: {
      id: 'cve-fix-region@1', unit: 'one CVE revision snapshot',
      match: 'open vulnerability finding within reviewed inclusive source region; exact advisory CWE and permitted rule/evidence criteria',
      parentLabel: 'positive for the cited fix-specific mechanism', fixLabel: 'negative for the cited fix-specific mechanism',
      missingKind: 'vulnerability', cweAliases: false, excludesUnsupportedCwes: false,
      context: 'source localization is a static benchmark proxy; does not prove exploitability or application safety',
    },
    ...scoreLocalized(localization.entries, observations),
  } : localization;
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
    unscoredFindings, cases, localized,
  };
  safeDirectory(out, true);
  writeReportFile(out, 'benchmark.json', JSON.stringify(report, null, 2) + '\n');
  writeReportFile(out, 'benchmark.md', toMarkdown(report));
  return report;
}

module.exports = { fetchCveCorpus, runCveBenchmark, toMarkdown, readLocalization, scoreLocalized };
