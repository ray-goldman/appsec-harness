'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { scan } = require('../src/engine');
async function findings(t, source) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kayfabe-go-scopes-'));
  t.after(() => {
    assert.equal(path.dirname(fs.realpathSync(root)), fs.realpathSync(os.tmpdir()));
    assert.ok(path.basename(root).startsWith('kayfabe-go-scopes-'));
    fs.rmSync(root, { recursive: true, force: true });
  });
  fs.writeFileSync(path.join(root, 'main.go'), source);
  return (await scan(root, { includeTests: true })).findings.filter(f => f.ruleId === 'GO-PATH-001');
}
const source = (body, extra = '') => `package main
import (
  "os"
  "net/http"
  "path/filepath"
)
func unrelated(r *http.Request) {
  name := r.FormValue("name")
  _ = name
}
${extra}
func read(w http.ResponseWriter, r *http.Request) {
  ${body}
}`;
test('Go local literals do not inherit a different function binding', async t => {
  assert.equal((await findings(t, source('name := "README.txt"\n  os.ReadFile(name)'))).length, 0);
  assert.equal((await findings(t, source('var name string = "README.txt"\n  os.ReadFile(name)'))).length, 0);
});
test('Go mutation, capture, unknown helpers, globals and nested shadowing retain warnings', async t => {
  for (const body of [
    'name := "README.txt"\n name = r.FormValue("name")\n os.ReadFile(name)',
    'name := "README.txt"\n update(&name)\n os.ReadFile(name)',
    'name := "README.txt"\n update(&(name))\n os.ReadFile(name)',
    'name := "README.txt"\n (name) = r.FormValue("name")\n os.ReadFile(name)',
    'name := "README.txt"\n ((name) ) = r.FormValue("name")\n os.ReadFile(name)',
    'if\n name := "README.txt";\n name != "" { println(name) }\n os.ReadFile(name)',
    'switch\n name := "README.txt";\n name { default: println(name) }\n os.ReadFile(name)',
    'for\n name := "README.txt";\n name != ""; name = "" { println(name) }\n os.ReadFile(name)',
    'name := "README.txt"\n func() { name = r.FormValue("name") }()\n os.ReadFile(name)',
    'name := helper()\n os.ReadFile(name)',
    'os.ReadFile(name)',
    'if true { name := "README.txt"; _ = name }\n os.ReadFile(name)',
    'name := "README.txt"\n if true { name := r.FormValue("name"); os.ReadFile(name) }',
  ]) assert.ok((await findings(t, source(body, 'var name string'))).length, body);
});
test('Go basename remains tainted without a containment proof even in isolation', async t => {
  const only = source('name := filepath.Base(r.FormValue("name"))\n os.ReadFile(filepath.Join("/srv/files", name))')
    .replace(/func unrelated[\s\S]*?\n}\n/, '');
  assert.ok((await findings(t, only)).length);
});
