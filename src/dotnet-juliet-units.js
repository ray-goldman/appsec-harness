'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { methodRegions } = require('./benchmark-juliet');
const CONFIDENCE = Object.freeze({ low: 0, medium: 1, high: 2 });
const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');

function normalizedFile(value) {
  if (typeof value !== 'string' || !value || value.includes('\0')) throw new Error('Juliet file path must be a nonempty string');
  const file = value.replaceAll('\\', '/').replace(/^\.\//, '');
  if (file.startsWith('/') || /^[A-Za-z]:/.test(file) || file.split('/').includes('..')) throw new Error('Juliet file path must be relative and confined');
  return file;
}

function validateJulietUnitManifest(manifest) {
  if (!manifest || manifest.schema !== 'kayfabe-juliet-dotnet-cross-file-units@1' ||
      !['not-measured', 'frozen'].includes(manifest.status) || manifest.dataset !== 'Juliet C# 1.3' ||
      manifest.confidenceThreshold !== 'low' || !Array.isArray(manifest.crossFileVariants)) return false;
  const ids = new Set(), variants = new Set();
  for (const item of manifest.crossFileVariants) {
    if (!item || typeof item.id !== 'string' || !item.id || !Array.isArray(item.variants) || !item.variants.length || ids.has(item.id)) return false;
    ids.add(item.id);
    for (const variant of item.variants) {
      if (typeof variant !== 'string' || !/^\d{2}(?:[a-z]|_(?:bad|base|good[a-z0-9]+))?$/i.test(variant) || variants.has(variant.toLowerCase())) return false;
      variants.add(variant.toLowerCase());
    }
  }
  for (const key of ['inputManifestSha256', 'labelsSha256']) {
    if (manifest[key] !== null && (typeof manifest[key] !== 'string' || !/^[a-f0-9]{64}$/.test(manifest[key]))) return false;
  }
  if (typeof manifest.sourceArchiveSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(manifest.sourceArchiveSha256)) return false;
  if (manifest.status === 'not-measured' && (typeof manifest.reasonNotMeasured !== 'string' || !manifest.reasonNotMeasured.trim())) return false;
  if (manifest.status === 'frozen' && (!manifest.inputManifestSha256 || !manifest.labelsSha256)) return false;
  return true;
}

function findUnitFinding(findings, unit, regions, minConfidence) {
  for (const finding of findings) {
    if (!Number.isInteger(finding.cwe) || finding.cwe !== unit.cwe) continue;
    const confidence = Object.hasOwn(CONFIDENCE, finding.confidence) ? CONFIDENCE[finding.confidence] : CONFIDENCE.low;
    if (confidence < minConfidence) continue;
    const file = normalizedFile(finding.file);
    const line = finding.line;
    if (!Number.isInteger(line) || line < 1) continue;
    if (regions.some(region => region.file === file && region.startLine <= line && region.endLine >= line)) return true;
  }
  return false;
}

function rate(numerator, denominator) {
  return denominator ? numerator / denominator : null;
}

function buildJulietUnits(labels, manifest) {
  if (!Array.isArray(labels) || !validateJulietUnitManifest(manifest)) throw new Error('invalid Juliet labels or cross-file manifest');
  const familyBySuffix = new Map();
  for (const family of manifest.crossFileVariants) for (const suffix of family.variants) familyBySuffix.set(suffix.toLowerCase(), family.id);
  const knownSuffixes = [...familyBySuffix.keys()].sort((a, b) => b.length - a.length);
  const normalizedLabels = [], labelIds = new Set(), unitsByKey = new Map();
  for (const label of labels) {
    if (!label || typeof label.id !== 'string' || !label.id || !Number.isInteger(label.cwe) ||
        typeof label.vulnerable !== 'boolean' || !Array.isArray(label.regions) || !label.regions.length) {
      throw new Error('invalid Juliet source label');
    }
    const regionsByFile = new Map();
    for (const region of label.regions) {
      if (!region || !Number.isInteger(region.startLine) || region.startLine < 1 ||
          !Number.isInteger(region.endLine) || region.endLine < region.startLine) throw new Error('invalid Juliet source label region');
      const file = normalizedFile(region.file);
      if (!regionsByFile.has(file)) regionsByFile.set(file, []);
      regionsByFile.get(file).push({ file, startLine: region.startLine, endLine: region.endLine });
    }
    for (const [file, regions] of regionsByFile) {
      const basename = file.slice(file.lastIndexOf('/') + 1);
      const suffix = knownSuffixes.find(token => basename.toLowerCase().endsWith(`_${token}.cs`));
      const crossFileFamily = suffix ? familyBySuffix.get(suffix) : undefined;
      const stem = crossFileFamily ? basename.slice(0, -(`_${suffix}.cs`).length) : basename;
      const familyKey = crossFileFamily
        ? `${file.slice(0, file.lastIndexOf('/') + 1)}${stem}#${crossFileFamily}`
        : file;
      const polarity = label.vulnerable ? 'bad' : 'good';
      const key = `${familyKey}:CWE-${label.cwe}:${polarity}`;
      let unit = unitsByKey.get(key);
      if (!unit) {
        unit = { id: `juliet:${familyKey}:CWE-${label.cwe}:${polarity}`, cwe: label.cwe, vulnerable: label.vulnerable, labelIds: [] };
        unitsByKey.set(key, unit);
      }
      const id = `${label.id}@${file}`;
      if (labelIds.has(id)) throw new Error(`duplicate Juliet source label: ${id}`);
      labelIds.add(id);
      normalizedLabels.push({ id, unitId: unit.id, cwe: label.cwe, vulnerable: label.vulnerable, regions });
      unit.labelIds.push(id);
    }
  }
  return { labels: normalizedLabels, units: [...unitsByKey.values()] };
}

function loadJulietCSharpUnits(root, files, manifest) {
  if (!Array.isArray(files) || !validateJulietUnitManifest(manifest)) throw new Error('invalid Juliet input files or cross-file manifest');
  const rootPath = fs.realpathSync(root), sourceLabels = [], seenFiles = new Set(), supportFilesWithoutPolarity = [];
  const declaredSupportSuffixes = new Set(manifest.crossFileVariants.flatMap(family => family.variants
    .filter(suffix => /_base$/i.test(suffix)).map(suffix => suffix.toLowerCase())));
  for (const rel of files) {
    const file = normalizedFile(rel);
    if (seenFiles.has(file)) throw new Error(`duplicate Juliet input file: ${file}`);
    seenFiles.add(file);
    if (!file.startsWith('src/testcases/') || !file.toLowerCase().endsWith('.cs')) continue;
    const full = path.resolve(rootPath, file);
    const relative = path.relative(rootPath, full);
    if (!relative || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) throw new Error(`Juliet input escapes dataset root: ${file}`);
    const stat = fs.lstatSync(full);
    if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`Juliet input is not a regular file: ${file}`);
    if (stat.size > 1024 * 1024) throw new Error(`Juliet C# testcase exceeds 1 MiB: ${file}`);
    const source = fs.readFileSync(full, 'utf8');
    const cwe = path.posix.basename(file).match(/^CWE0*(\d+)_/i)?.[1];
    if (!cwe) continue; // Per-CWE Program.cs and other harness helpers are scanned but have no Juliet testcase label.
    if (!Number(cwe)) throw new Error(`Juliet C# testcase has an invalid filename CWE: ${file}`);
    const totalLines = source.split(/\r?\n/).length;
    const regions = methodRegions(source, file, 'csharp');
    const classPolarity = path.posix.basename(file).match(/_(good\w*|bad)\.cs$/i)?.[1];
    const badRegions = classPolarity
      ? (classPolarity.toLowerCase().startsWith('good') ? [] : [{ file, startLine: 1, endLine: totalLines }])
      : regions.filter(region => /^Bad(?:[A-Z0-9_]|$)/.test(region.name));
    const goodRegions = classPolarity
      ? (classPolarity.toLowerCase().startsWith('good') ? [{ file, startLine: 1, endLine: totalLines }] : [])
      : regions.filter(region => /^Good(?:[A-Z0-9_]|$)/.test(region.name));
    if (!badRegions.length && !goodRegions.length) {
      const supportSuffix = [...declaredSupportSuffixes].find(suffix => path.posix.basename(file).toLowerCase().endsWith(`_${suffix}.cs`));
      if (supportSuffix || /_helper(?:\w*)?\.cs$/i.test(path.posix.basename(file))) { supportFilesWithoutPolarity.push(file); continue; }
      throw new Error(`Juliet C# testcase has no labeled Bad/Good method regions: ${file}`);
    }
    if (badRegions.length) sourceLabels.push({ id: `${file}:CWE-${Number(cwe)}:bad`, cwe: Number(cwe), vulnerable: true, regions: badRegions });
    if (goodRegions.length) sourceLabels.push({ id: `${file}:CWE-${Number(cwe)}:good`, cwe: Number(cwe), vulnerable: false, regions: goodRegions });
  }
  if (!sourceLabels.length) throw new Error('no labeled Juliet C# testcase files found');
  const grouped = buildJulietUnits(sourceLabels, manifest);
  const labelsById = new Map(grouped.labels.map(label => [label.id, label]));
  const labels = grouped.units.map(unit => ({
    id: unit.id,
    cwe: unit.cwe,
    vulnerable: unit.vulnerable,
    regions: unit.labelIds.flatMap(id => labelsById.get(id).regions),
  }));
  return {
    labels,
    units: grouped.units,
    sourceLabelCount: sourceLabels.length,
    supportFilesWithoutPolarity,
    labelsSha256: sha256(JSON.stringify(labels)),
  };
}

function scoreJulietUnits({ findings, labels, units, confidenceThreshold = 'low' }) {
  if (!Array.isArray(findings) || !Array.isArray(labels) || !Array.isArray(units)) throw new TypeError('findings, labels, and units must be arrays');
  if (!Object.hasOwn(CONFIDENCE, confidenceThreshold)) throw new Error('unsupported Juliet confidence threshold');
  const labelsById = new Map();
  for (const label of labels) {
    if (!label || typeof label.id !== 'string' || !label.id || labelsById.has(label.id) ||
        !Number.isInteger(label.cwe) || typeof label.vulnerable !== 'boolean' || !Array.isArray(label.regions) || !label.regions.length) {
      throw new Error('invalid or duplicate Juliet label');
    }
    const regions = label.regions.map(region => {
      if (!region || !Number.isInteger(region.startLine) || region.startLine < 1 ||
          !Number.isInteger(region.endLine) || region.endLine < region.startLine) throw new Error('invalid Juliet label region');
      return { file: normalizedFile(region.file), startLine: region.startLine, endLine: region.endLine };
    });
    labelsById.set(label.id, { ...label, regions });
  }
  const seenUnitIds = new Set(), usedLabels = new Set();
  const totals = { cases: 0, tp: 0, fp: 0, tn: 0, fn: 0 };
  const byCwe = new Map();
  const minConfidence = CONFIDENCE[confidenceThreshold];
  for (const unit of units) {
    if (!unit || typeof unit.id !== 'string' || !unit.id || seenUnitIds.has(unit.id) ||
        !Number.isInteger(unit.cwe) || typeof unit.vulnerable !== 'boolean' ||
        !Array.isArray(unit.labelIds) || !unit.labelIds.length || new Set(unit.labelIds).size !== unit.labelIds.length) {
      throw new Error('invalid or duplicate Juliet scoring unit');
    }
    seenUnitIds.add(unit.id);
    const regions = [];
    for (const id of unit.labelIds) {
      const label = labelsById.get(id);
      if (!label || usedLabels.has(id) || label.cwe !== unit.cwe || label.vulnerable !== unit.vulnerable ||
          (label.unitId !== undefined && label.unitId !== unit.id)) throw new Error(`inconsistent Juliet unit label: ${id}`);
      usedLabels.add(id);
      regions.push(...label.regions);
    }
    const detected = findUnitFinding(findings, unit, regions, minConfidence);
    const row = byCwe.get(unit.cwe) || { cwe: unit.cwe, cases: 0, tp: 0, fp: 0, tn: 0, fn: 0 };
    totals.cases++; row.cases++;
    if (unit.vulnerable) {
      if (detected) { totals.tp++; row.tp++; } else { totals.fn++; row.fn++; }
    } else if (detected) { totals.fp++; row.fp++; }
    else { totals.tn++; row.tn++; }
    byCwe.set(unit.cwe, row);
  }
  if (usedLabels.size !== labelsById.size) throw new Error('unscored Juliet labels remain outside the unit manifest');
  totals.recall = rate(totals.tp, totals.tp + totals.fn);
  totals.precision = rate(totals.tp, totals.tp + totals.fp);
  const rows = [...byCwe.values()].sort((a, b) => a.cwe - b.cwe).map(row => ({
    ...row,
    recall: rate(row.tp, row.tp + row.fn),
    precision: rate(row.tp, row.tp + row.fp),
  }));
  return { confidenceThreshold, totals, byCwe: rows };
}

module.exports = { buildJulietUnits, loadJulietCSharpUnits, scoreJulietUnits, validateJulietUnitManifest };
