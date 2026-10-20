'use strict';
const path = require('node:path');
const { checkedFile } = require('./benchmark');
const { datasetRoot, inventory, readBounded, sha256, runLabeled, regionIndex, markdown } = require('./benchmark-labeled');

function resolveUri(root, manifest, location) {
  if (!location || typeof location.uri !== 'string' || location.uriBaseId !== undefined) throw new Error(`missing URI or unsupported uriBaseId in ${manifest}`);
  const uri = location.uri;
  if (!uri || /[\\:?#\0]/.test(uri) || uri.startsWith('/')) throw new Error(`non-relative SARD artifact URI in ${manifest}`);
  let decoded;
  try { decoded = decodeURIComponent(uri); } catch { throw new Error(`invalid URI encoding in ${manifest}`); }
  if (/[\\:?#\0]/.test(decoded) || decoded.split('/').some((x) => !x || x === '.' || x === '..')) throw new Error(`unsafe SARD artifact URI in ${manifest}`);
  const file = path.posix.join(path.posix.dirname(manifest), decoded);
  checkedFile(root, file);
  return file;
}

function cweOf(result, manifest) {
  const values = new Set();
  if (typeof result.ruleId === 'string' && /^CWE-[1-9]\d{0,4}$/.test(result.ruleId)) values.add(Number(result.ruleId.slice(4)));
  for (const taxon of result.taxa || []) {
    if (taxon.toolComponent?.name !== 'CWE') continue;
    if (!/^[1-9]\d{0,4}$/.test(String(taxon.id))) throw new Error(`invalid SARD CWE taxon in ${manifest}`);
    values.add(Number(taxon.id));
  }
  if (values.size !== 1) throw new Error(`missing or conflicting SARD CWE in ${manifest}`);
  return [...values][0];
}

function polarity(result, state, manifest) {
  const flags = new Set();
  if (result.kind === 'fail') flags.add('bad');
  else if (result.kind === 'pass') flags.add('good');
  else if (result.kind !== undefined) throw new Error(`unsupported SARD result kind in ${manifest}`);
  const explicit = result.properties?.state;
  if (explicit !== undefined) {
    if (!['bad', 'good'].includes(explicit)) throw new Error(`unsupported SARD result state in ${manifest}`);
    flags.add(explicit);
  }
  if (state !== 'mixed') flags.add(state);
  if (flags.size !== 1) throw new Error(`ambiguous/conflicting SARD flaw/fix polarity in ${manifest}`);
  return [...flags][0];
}

function loadSard(root, manifests) {
  const labels = [], artifacts = [], seen = new Set();
  const states = { bad: 0, good: 0, mixed: 0 };
  for (const manifest of manifests) {
    let document;
    try { document = JSON.parse(readBounded(root, manifest, 16 * 1024 * 1024).toString('utf8')); } catch (error) { throw new Error(`invalid SARD manifest ${manifest}: ${error.message}`); }
    if (document.version !== '2.1.0' || !Array.isArray(document.runs) || !document.runs.length) throw new Error(`SARIF 2.1.0 runs required in ${manifest}`);
    for (const [runIndex, run] of document.runs.entries()) {
      const state = run.properties?.state;
      if (!Object.hasOwn(states, state)) throw new Error(`explicit SARD bad/good/mixed state required in ${manifest}`);
      states[state]++;
      if (run.originalUriBaseIds && Object.keys(run.originalUriBaseIds).length) throw new Error(`unsupported SARD URI base IDs in ${manifest}`);
      if (!Array.isArray(run.artifacts) || !run.artifacts.length || !Array.isArray(run.results) || !run.results.length) {
        throw new Error(`explicit SARD artifacts and flaw/fix results required in ${manifest}`);
      }
      const runArtifacts = run.artifacts.map((artifact) => {
        const file = resolveUri(root, manifest, artifact.location), bytes = readBounded(root, file);
        if (artifact.length !== undefined && artifact.length !== bytes.length) throw new Error(`SARD artifact length mismatch: ${file}`);
        const hashes = artifact.hashes || {};
        for (const [algorithm, value] of Object.entries(hashes)) {
          if (algorithm.toLowerCase().replace(/-/g, '') !== 'sha256') continue;
          if (typeof value !== 'string' || !/^[a-f0-9]{64}$/i.test(value) || sha256(bytes) !== value.toLowerCase()) throw new Error(`SARD artifact SHA-256 mismatch: ${file}`);
        }
        const info = { manifest, runIndex, file, hashes, sha256: sha256(bytes), lines: bytes.toString('utf8').split('\n').length };
        artifacts.push(info);
        return info;
      });
      for (const [resultIndex, result] of run.results.entries()) {
        const cwe = cweOf(result, manifest), stateLabel = polarity(result, state, manifest);
        if (!Array.isArray(result.locations) || !result.locations.length) throw new Error(`explicit SARD location required in ${manifest}`);
        for (const [locationIndex, location] of result.locations.entries()) {
          const physical = location.physicalLocation, loc = physical?.artifactLocation;
          if (!loc || loc.uriBaseId !== undefined) throw new Error(`SARD physical artifact location required in ${manifest}`);
          let artifact;
          if (loc.index !== undefined) {
            if (!Number.isInteger(loc.index) || loc.index < 0 || loc.index >= runArtifacts.length) throw new Error(`invalid SARD artifact index in ${manifest}`);
            artifact = runArtifacts[loc.index];
            if (loc.uri !== undefined && resolveUri(root, manifest, loc) !== artifact.file) throw new Error(`SARD artifact URI/index mismatch in ${manifest}`);
          } else {
            const file = resolveUri(root, manifest, loc), found = runArtifacts.filter((x) => x.file === file);
            if (found.length !== 1) throw new Error(`undeclared/ambiguous SARD artifact in ${manifest}`);
            artifact = found[0];
          }
          const region = physical.region, start = region?.startLine, end = region?.endLine ?? start;
          if (!Number.isInteger(start) || !Number.isInteger(end) || start < 1 || end < start || end > artifact.lines) throw new Error(`invalid SARD labeled line range in ${manifest}`);
          const key = `${artifact.file}:${start}:${end}:CWE-${cwe}`;
          if (seen.has(key)) throw new Error(`duplicate or conflicting SARD label: ${key}`);
          seen.add(key);
          labels.push({
            id: `${manifest}:run-${runIndex + 1}:result-${resultIndex + 1}:location-${locationIndex + 1}`,
            sardId: run.properties.id ?? null, cwe, vulnerable: stateLabel === 'bad', state: stateLabel, manifest,
            regions: [{ file: artifact.file, startLine: start, endLine: end, basis: `explicit SARIF ${stateLabel} result location` }],
          });
        }
      }
    }
  }
  if (!labels.length) throw new Error('no explicit SARD labels');
  return { labels, metadata: { states, artifacts, manifestCount: manifests.length } };
}

async function runSardBenchmark(directory, opts = {}) {
  const root = datasetRoot(directory), files = inventory(root);
  const manifests = opts.expected ? [opts.expected] : files.filter((file) => path.posix.basename(file) === 'manifest.sarif');
  if (!manifests.length) throw new Error('no SARD manifest.sarif files found');
  const { labels, metadata } = loadSard(root, manifests);
  return runLabeled(root, opts, {
    name: 'NIST SARD', source: 'https://samate.nist.gov/SARD/', defaultOut: 'appsec-reports/benchmarks/sard',
    labels, metadata, inputFiles: files, manifestFiles: manifests, regionsByFile: regionIndex(labels),
    policy: {
      id: 'sard-sarif-location-cwe@1', unit: 'one explicit SARIF result location × CWE × polarity',
      match: 'open finding with exact source path and CWE and start line at the labeled line, or within an explicitly supplied inclusive upstream line range',
      limitations: [
        'A bad/good run state labels its explicit result locations; mixed runs require an explicit result kind fail/pass or properties.state bad/good. Missing or conflicting metadata is rejected.',
        'No safe locations are inferred from absent results. Datasets with only bad labels have no negative denominator and FPR is n/a.',
        'Exact labeled locations can miss a valid detection reported at a nearby source or sink; no line tolerance, CWE aliases, or file-level fallback is applied.',
        'Artifacts are checked against supplied byte length and SHA-256; declared hashes and computed hashes are retained in JSON. Other hash algorithms are preserved but not verified.',
        'URI base IDs, remote/absolute URIs, parent traversal, symbolic links, ambiguous artifacts, duplicate labels, and missing labeled files are rejected.',
      ],
    },
  });
}

module.exports = { runSardBenchmark, toMarkdown: markdown, loadSard, resolveUri };
