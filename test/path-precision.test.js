'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { scan } = require('../src/engine');
const { pathSinkFilter } = require('../src/path-proofs');
const { stripComments } = require('../src/languages');

async function hits(t, file, code, rule, extra = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kayfabe-path-'));
  t.after(() => {
    assert.equal(path.dirname(fs.realpathSync(root)), fs.realpathSync(os.tmpdir()));
    assert.ok(path.basename(root).startsWith('kayfabe-path-'));
    fs.rmSync(root, { recursive: true, force: true });
  });
  for (const [name, text] of Object.entries({ [file]: code, ...extra })) {
    fs.mkdirSync(path.dirname(path.join(root, name)), { recursive: true });
    fs.writeFileSync(path.join(root, name), text);
  }
  return (await scan(root, { includeTests: true })).findings.filter(f => f.ruleId === rule);
}
const java = (body, field = 'private static final Path ROOT = Paths.get("/srv/files").toAbsolutePath();', params = '@RequestParam String file') => `
import java.nio.file.*;
import java.io.IOException;
import org.springframework.web.bind.annotation.*;
public class Example {
  ${field}
  public byte[] read(${params}) throws IOException {
    ${body}
  }
}`;
const javaBody = `Path p = ROOT.resolve(file).normalize();
    if (!p.startsWith(ROOT)) throw new SecurityException("bad path");
    return Files.readAllBytes(p);`;
const go = guard => `package main
import (
  "net/http"
  "path/filepath"
  "os"
)
const root = "/srv/files"
func other(r *http.Request) {
  name := r.FormValue("name")
  _ = name
}
func read(w http.ResponseWriter, r *http.Request) {
  name := filepath.Base(r.URL.Query().Get("name"))
  ${guard}
  data, _ := os.ReadFile(filepath.Join(root, name))
  w.Write(data)
}`;

test('Java normalized path guard covers the same local path and rejecting branch', async t => {
  assert.equal((await hits(t, 'Example.java', java(javaBody), 'JAVA-PATH-001')).length, 0);
});
test('Java path proof rejects mutations, wrong guards, wrong roots and alternate paths', async t => {
  for (const body of [
    javaBody.replace('!p.startsWith', 'p.startsWith'),
    javaBody.replace('.normalize()', ''),
    javaBody.replace('throw new SecurityException("bad path");', 'System.out.println("bad path");'),
    javaBody.replace('p.startsWith(ROOT)', 'p.toString().startsWith(ROOT.toString())'),
    javaBody.replace('return Files', 'p = ROOT.resolve(file); return Files'),
    javaBody.replace('readAllBytes(p)', 'readAllBytes(ROOT.resolve(file))'),
    javaBody.replace('if (!p', 'if (false) if (!p'),
    javaBody.replace('if (!p', 'try { if (!p').replace('return Files', '} catch (Exception e) {} return Files'),
  ]) assert.ok((await hits(t, 'Example.java', java(body), 'JAVA-PATH-001')).length, body);
  for (const field of ['private static Path ROOT = Paths.get("/srv/files");',
    'private static final Path ROOT = Paths.get("relative");']) {
    assert.ok((await hits(t, 'Example.java', java(javaBody, field), 'JAVA-PATH-001')).length);
  }
  assert.ok((await hits(t, 'Example.java', java(javaBody, undefined, '@RequestParam String file, Path ROOT'), 'JAVA-PATH-001')).length);
  assert.ok((await hits(t, 'Example.java', java(javaBody), 'JAVA-PATH-001', { 'Path.java': 'class Path {}' })).length);
});
test('Go basename needs a local-path rejecting guard before the file read', async t => {
  assert.equal((await hits(t, 'main.go', go('if !filepath.IsLocal(name) { return }'), 'GO-PATH-001')).length, 0);
  for (const guard of ['', 'if filepath.IsLocal(name) { return }',
    'if !filepath.IsLocal(name) { w.Write(nil) }',
    'if !filepath.IsLocal(name) { return }; name = r.FormValue("other")']) {
    assert.ok((await hits(t, 'main.go', go(guard), 'GO-PATH-001')).length, guard);
  }
});

test('Java path proof requires standard owner and String bindings', async t => {
  for (const source of [
    'import static external.Factory.Paths;\n' + java(javaBody),
    'import static external.Factory.*;\n' + java(javaBody),
    'import external.String;\n' + java(javaBody),
    java(javaBody, 'private static external.Factory<String>Paths = new external.Factory<String>();\n' +
      'private static final Path ROOT = Paths.get("/srv/files").toAbsolutePath();'),
  ]) assert.ok((await hits(t, 'Example.java', source, 'JAVA-PATH-001')).length);
  assert.ok((await hits(t, 'Example.java', java(javaBody), 'JAVA-PATH-001', {
    'String.java': 'class String {}',
  })).length);
});

test('Go path proof rejects alternate package owners and source-looking raw strings', () => {
  const good = go('if !filepath.IsLocal(name) { return }');
  const proves = raw => {
    const proof = pathSinkFilter({ file: 'main.go', lang: 'go', raw, code: stripComments(raw, 'go') });
    return raw.split('\n').some((line, i) => line.includes('os.ReadFile') && proof('GO-PATH-001', i));
  };
  assert.equal(proves(good), true);
  for (const raw of [
    good.replace('"path/filepath"', 'filepath "example.test/paths"'),
    good.replace('const root = "/srv/files"', 'var root = "/srv/files"'),
    good.replace('const root = "/srv/files"', 'var text = `\nconst root = "/srv/files"\n`'),
    good.replace('"path/filepath"', 'filepath "example.test/paths"') + '\nvar text = `\nimport "path/filepath"\n`',
    good.replace('if !filepath', 'name = r.FormValue("other")\nif !filepath'),
    good.replace('w.Write(data)', 'w.Write(data)\nname = r.FormValue("other")'),
  ]) assert.equal(proves(raw), false, raw);
});
