'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { tokenizeCSharp } = require('../src/parsers/csharp/lexer');

test('null-coalescing assignment is one mutation token', () => {
  assert.deepEqual(tokenizeCSharp('value ??= input;').tokens.map(t=>t.text),['value','??=','input',';']);
});

test('tokenizes comments, char literals, string forms and preserves directive regions', () => {
  const source = `// comment\nchar c = 'x'; var a = "text"; var b = @"path"; var c = $"{Call(1):X}"; var d = """raw"""u8;\n#if OMITBAD\nBad();\n#else\nGood();\n#endif`;
  const result = tokenizeCSharp(source);
  assert.deepEqual(result.errors, []);
  assert.ok(result.tokens.some(t => t.kind === 'identifier' && t.text === 'Bad'));
  assert.ok(result.tokens.some(t => t.kind === 'identifier' && t.text === 'Good'));
  assert.ok(result.regions.some(r => r.kind === 'preprocessor' && r.directive === 'if'));
  assert.ok(result.tokens.some(t => t.kind === 'interpolated-string' && t.text.includes('Call')));
});

test('unterminated lexical forms and unmatched directives make the stream incomplete', () => {
  for (const source of ['var x = "open;', '/* open', "'x", '#if A\nx();']) {
    const result = tokenizeCSharp(source);
    assert.ok(result.errors.length, source);
  }
});
