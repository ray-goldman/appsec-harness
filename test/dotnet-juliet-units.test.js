'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { buildJulietUnits, scoreJulietUnits, validateJulietUnitManifest } = require('../src/dotnet-juliet-units');
const manifest = require('../docs/benchmarks/dotnet-juliet-cross-file-units.json');

test('cross-file suffix files become one testcase unit for each polarity', () => {
  const built = buildJulietUnits([
    { id: 'bad-source', cwe: 89, vulnerable: true, regions: [{ file: 'src/CWE89/CWE89_SQL__Web_22a.cs', startLine: 10, endLine: 20 }] },
    { id: 'bad-sink', cwe: 89, vulnerable: true, regions: [{ file: 'src/CWE89/CWE89_SQL__Web_22b.cs', startLine: 4, endLine: 14 }] },
    { id: 'good-source', cwe: 89, vulnerable: false, regions: [{ file: 'src/CWE89/CWE89_SQL__Web_22a.cs', startLine: 22, endLine: 30 }] },
    { id: 'good-sink', cwe: 89, vulnerable: false, regions: [{ file: 'src/CWE89/CWE89_SQL__Web_22b.cs', startLine: 16, endLine: 25 }] },
  ], manifest);
  assert.equal(built.units.length, 2);
  assert.deepEqual(built.units.map(unit => unit.labelIds.length), [2, 2]);
  assert.ok(built.units.every(unit => unit.id.includes('22a/b')));
});

test('a cross-file Juliet testcase counts once and matches a finding in any labeled file region', () => {
  const result = scoreJulietUnits({
    findings: [{ file: 'src/Flow/Repository.cs', line: 19, cwe: 89, confidence: 'high' }],
    labels: [
      { id: 'controller', unitId: 'CWE-89:51a:vulnerable', cwe: 89, vulnerable: true, regions: [{ file: 'src/Web/OrdersController.cs', startLine: 10, endLine: 24 }] },
      { id: 'repository', unitId: 'CWE-89:51a:vulnerable', cwe: 89, vulnerable: true, regions: [{ file: 'src/Flow/Repository.cs', startLine: 15, endLine: 21 }] },
    ],
    units: [{ id: 'CWE-89:51a:vulnerable', cwe: 89, vulnerable: true, labelIds: ['controller', 'repository'] }],
    confidenceThreshold: 'low',
  });
  assert.deepEqual(result.totals, { cases: 1, tp: 1, fp: 0, tn: 0, fn: 0, recall: 1, precision: 1 });
});

test('safe testcase units count a matching finding as one false positive', () => {
  const result = scoreJulietUnits({
    findings: [{ file: 'src/Safe/Lookup.cs', line: 8, cwe: 89, confidence: 'low' }],
    labels: [{ id: 'safe', unitId: 'CWE-89:81:safe', cwe: 89, vulnerable: false, regions: [{ file: 'src/Safe/Lookup.cs', startLine: 3, endLine: 12 }] }],
    units: [{ id: 'CWE-89:81:safe', cwe: 89, vulnerable: false, labelIds: ['safe'] }],
    confidenceThreshold: 'low',
  });
  assert.equal(result.totals.fp, 1);
  assert.equal(result.totals.cases, 1);
});

test('the frozen manifest names the cross-file Juliet families and validates input provenance', () => {
  assert.equal(validateJulietUnitManifest(manifest), true);
  assert.deepEqual(manifest.crossFileVariants.map(item => item.id), ['22a/b', '51', '52', '53', '54', '61', '66', '67', '68', '71', '72', '73', '74', '75', '81']);
  const tampered = structuredClone(manifest);
  tampered.sourceArchiveSha256 = 'not-a-hash';
  assert.equal(validateJulietUnitManifest(tampered), false);
});
