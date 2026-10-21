'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { storedDataFindings } = require('../src/csharp-checks');

test('stored-data checks are opt-in, low confidence, and have safe encoding/parameterized twins', () => {
  const xss = 'var html = File.ReadAllText(path); return Html.Raw(html);';
  assert.deepEqual(storedDataFindings({ file: 'A.cs', code: xss }), []);
  const found = storedDataFindings({ file: 'A.cs', code: xss, options: { dotnetStoredData: true } });
  assert.equal(found[0].ruleId, 'CS-STORED-XSS-001');
  assert.equal(found[0].confidence, 'low');
  assert.deepEqual(storedDataFindings({ file: 'A.cs', code: 'var html = File.ReadAllText(path); var safe = HtmlEncoder.Default.Encode(html); return Html.Raw(safe);', options: { dotnetStoredData: true } }), []);
  assert.deepEqual(storedDataFindings({ file: 'A.cs', code: 'var sql = File.ReadAllText(path); db.FromSqlInterpolated($"select * from T where x={sql}");', options: { dotnetStoredData: true } }), []);
});

test('stored raw SQL findings have a distinct opt-in ID and low confidence', () => {
  const findings = storedDataFindings({ file: 'A.cs', code: 'var sql = File.ReadAllText(path); db.FromSqlRaw(sql);', options: { dotnetStoredData: true } });
  assert.equal(findings[0].ruleId, 'CS-SECONDARY-SQL-001');
  assert.equal(findings[0].confidence, 'low');
});
