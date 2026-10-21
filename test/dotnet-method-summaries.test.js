'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { summarizeMethod } = require('../src/dotnet/method-summaries');

test('summarizes parameter returns, request sources, and category-specific sinks', () => {
  const summary = summarizeMethod({ id:'N.C.M/1(string)', parameters:[{name:'value',type:'string'}], body:'db.ExecuteSqlRaw(value); return Request.Query["q"];' });
  assert.deepEqual(summary.parameterToReturn, []);
  assert.ok(summary.parameterToSinks.some(x => x.parameter === 0 && x.category === 'sql'));
  assert.ok(summary.sourcesToReturn.includes('request'));
  const encoded = summarizeMethod({ id:'N.C.Html/1(string)', parameters:[{name:'value'}], body:'Html.Raw(HtmlEncoder.Default.Encode(value));' });
  assert.notEqual(encoded.sanitizersBySink.xss, true);
  assert.equal(encoded.sanitizersBySink.sql, undefined);
});

test('comments and literal contents do not manufacture flows', () => {
  const summary = summarizeMethod({id:'A',parameters:[{name:'value'}],body:'/* return value; db.ExecuteSqlRaw(value); */ return "value";'});
  assert.deepEqual(summary.parameterToReturn, []);
  assert.deepEqual(summary.parameterToSinks, []);
});

test('a sanitizer beside raw input never establishes safety for the whole argument', () => {
  const summary = summarizeMethod({id:'A',parameters:[{name:'value'}],body:'Html.Raw(HtmlEncoder.Default.Encode("fixed") + value);'});
  assert.notEqual(summary.sanitizersBySink.xss, true);
  assert.ok(summary.parameterToSinks.some(s=>s.parameter===0 && !s.sanitized));
});

test('parameter overwrites and unsupported control flow cannot manufacture direct flows', () => {
  for (const body of ['value = "fixed"; return value;', 'if (false) { return value; } return "fixed";']) {
    const summary = summarizeMethod({id:'A',parameters:[{name:'value'}],body});
    assert.deepEqual(summary.parameterToReturn, []);
    assert.ok(summary.unresolvedCallSites.length > 0);
  }
});

test('summarizes direct parameter-to-return flow', () => {
  const summary = summarizeMethod({ id:'N.C.Id/1(string)', parameters:[{name:'value'}], body:'return value;' });
  assert.deepEqual(summary.parameterToReturn, [0]);
});
