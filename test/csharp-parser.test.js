'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { parseCSharp } = require('../src/parsers/csharp/parser');

test('parses bounded type, member, lambda, and control-flow syntax with source spans', () => {
  const source = `namespace N { public partial record R(string Name) { private string field; public string P { get; set; } public R() {} public string Read(string x) { Func<string,string> f = y => y.Trim(); if (x != null) return f(x); else throw new Exception(); } } }`;
  const result = parseCSharp(source);
  assert.equal(result.complete, true, JSON.stringify(result.errors));
  assert.ok(result.declarations.some(d => d.kind === 'record' && d.name === 'R'));
  assert.ok(result.methods.some(m => m.name === 'Read' && m.statements.some(s => s.kind === 'if')));
  assert.ok(result.methods.every(m => m.start < m.end));
});

test('unsupported goto, unsafe, or malformed constructs report incomplete coverage', () => {
  for (const source of ['class C { void M(){ goto L; L: return; } }', 'class C { unsafe void M() {} }', 'class C { void M( {']) {
    assert.equal(parseCSharp(source).complete, false, source);
  }
});
