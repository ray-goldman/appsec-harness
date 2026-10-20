'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { scan } = require('../src/engine');
const { toSarif } = require('../src/report/sarif');
const { toMarkdown } = require('../src/report/markdown');
const { buildTriageRequest } = require('../src/triage');

test('SARIF retains PHP source evidence and explicit review classification', async () => {
  const result = await scan(path.join(__dirname, '../corpus/php-code-precision/vuln'));
  const finding = result.findings.find(f => f.ruleId === 'PHP-CODE-001');
  const vulnerability = toSarif(result).runs[0].results.find(f => f.ruleId === finding.ruleId);
  assert.match(vulnerability.message.text, /tainted: \$_POST from line \d+/);
  assert.equal(vulnerability.properties.kind, 'vulnerability');
  assert.match(toMarkdown(result), /Data flow: `\$_POST` \(tainted at line \d+\)/);
  assert.equal(buildTriageRequest(result).items.find(f => f.ruleId === finding.ruleId).kind, 'vulnerability');
  const review = toSarif({ ...result, findings: [{
    ...finding, kind: 'review', severity: 'low', confidence: 'low', taint: undefined,
  }] }).runs[0].results[0];
  assert.equal(review.properties.kind, 'review');
  assert.equal(review.level, 'note');
  assert.doesNotMatch(review.message.text, /undefined/);
});
