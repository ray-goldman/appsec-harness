'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { methodRegions } = require('../src/benchmark-juliet');

test('C# Juliet method regions include supported method modifiers and ignore strings and using blocks', () => {
  const regions = methodRegions(`using System;
class Sample {
    public override void Bad(int value) {
        string text = "{ not a brace }";
        using (var resource = new System.IO.MemoryStream()) { resource.WriteByte(1); }
        if (value > 0) { Console.WriteLine(text); }
    }
    private void GoodSafe() { Console.WriteLine("safe"); }
}`, 'Sample.cs', 'csharp');
  assert.deepEqual(regions.map(({ name, startLine, endLine }) => ({ name, startLine, endLine })), [
    { name: 'Bad', startLine: 3, endLine: 7 },
    { name: 'GoodSafe', startLine: 8, endLine: 8 },
  ]);
});
