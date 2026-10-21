'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { analyzeCSharpFile } = require('../src/parsers/csharp/coverage');

test('complete C# parse selects structural context and malformed input selects regex fallback', () => {
  const parsed = analyzeCSharpFile('src/A.cs', 'class A { public void M() { return; } }');
  assert.equal(parsed.complete, true);
  assert.equal(parsed.fallback, false);
  assert.ok(parsed.findingsContext.methods.length);
  const failed = analyzeCSharpFile('src/B.cs', 'class B { public void M() { "unfinished; }');
  assert.equal(failed.complete, false);
  assert.equal(failed.fallback, true);
  assert.equal(failed.findingsContext, null);
});

test('.cshtml and .razor stay on the regex path and are excluded from parser coverage', () => {
  for (const file of ['Views/Home.cshtml', 'Pages/Home.razor']) {
    const result = analyzeCSharpFile(file, 'class A {}');
    assert.equal(result.coverage.eligible, false);
    assert.equal(result.fallback, true);
  }
});
