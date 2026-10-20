'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { scoreLines } = require('../scripts/score-supplied-apps');

test('supplied app scoring requires an exact CWE and location, not an OWASP category', () => {
  const files = [{ file: 'app.js', text: '// BENCH vuln A05 CWE-89 sql\nquery(input);\n\n\n// BENCH safe A05 CWE-79 html\nprint(clean);' }];
  const result = scoreLines(files, [
    { file: 'app.js', line: 2, cwe: [79], owasp: 'A05', ruleId: 'wrong-mechanism' },
    { file: 'other.js', line: 2, cwe: [89], ruleId: 'wrong-file' },
    { file: 'app.js', line: 6, cwe: [79], ruleId: 'xss' },
  ]);
  assert.deepEqual(result.totals, { cases: 2, tp: 0, fp: 1, tn: 0, fn: 1 });
  assert.equal(result.unmatched.length, 2);
});

test('one finding credits only the nearest compatible supplied label', () => {
  const result = scoreLines([{ file: 'a.py', text: '# BENCH vuln A05 CWE-89 first\nquery(x)\n# BENCH safe A05 CWE-89 second\nquery(y)' }],
    [{ file: 'a.py', line: 4, cwe: [89], ruleId: 'sql' }]);
  assert.deepEqual(result.totals, { cases: 2, tp: 0, fp: 1, tn: 0, fn: 1 });
});
