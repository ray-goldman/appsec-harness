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
  assert.equal(encoded.sanitizersBySink.xss, true);
  assert.equal(encoded.sanitizersBySink.sql, undefined);
});

test('summarizes direct parameter-to-return flow', () => {
  const summary = summarizeMethod({ id:'N.C.Id/1(string)', parameters:[{name:'value'}], body:'return value;' });
  assert.deepEqual(summary.parameterToReturn, [0]);
});
