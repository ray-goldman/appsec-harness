'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { compareVersions, inRange, redact } = require('../src/util');
const { stripComments, maskStrings, analyzeTaint } = require('../src/languages');
const { validateUrl, validateRef, quarantine } = require('../src/clone');
const { scan, callArgs } = require('../src/engine');
const { validateTriage, mergeTriage, gate } = require('../src/triage');
const { toHtml } = require('../src/report/html');
const { toSarif } = require('../src/report/sarif');
const { toJUnit } = require('../src/report/junit');
const { validateRules, ALL } = require('../src/rules');

test('workflow injection stops at sibling keys after a sequence run key', () => {
  const rule = ALL.find(r => r.id === 'GHA-INJ-001');
  const event = '${{ github.event.pull_request.title }}';
  for (const spacing of [' ', '   ']) {
    const sibling = ' '.repeat(6 + 1 + spacing.length);
    for (const value of ['echo "$TITLE"', '|', '>-']) {
      const lines = [`      -${spacing}run: ${value}`];
      if (value !== 'echo "$TITLE"') lines.push(`${sibling}  echo "$TITLE"`);
      lines.push(`${sibling}env:`, `${sibling}  TITLE: ${event}`);
      assert.deepEqual(rule.check({ lines }), [], lines.join('\n'));
    }
  }
});

test('workflow injection keeps inline and multiline script findings', () => {
  const rule = ALL.find(r => r.id === 'GHA-INJ-001');
  const event = '${{ github.event.pull_request.title }}';
  for (const prefix of ['      - run:', '        run:', '      -   run:']) {
    const column = prefix.indexOf('run');
    assert.equal(rule.check({ lines: [`${prefix} echo "${event}"`] }).length, 1);
    for (const value of ['|', '|-', '>+', '|2', 'echo first']) {
      const lines = [`${prefix} ${value}`, `${' '.repeat(column + 2)}echo "${event}"`];
      assert.deepEqual(rule.check({ lines }).map(f => f.line), [2]);
    }
  }
  assert.deepEqual(rule.check({ lines: ['        script: |', `          console.log('${event}')`] }).map(f => f.line), [2]);
});

function tmpdir(files) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'appsec-unit-'));
  for (const [rel, content] of Object.entries(files)) {
    const p = path.join(d, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, content);
  }
  return d;
}

test('rule catalogue is well-formed', () => {
  assert.deepEqual(validateRules(), []);
  assert.ok(ALL.length > 150);
});

test('no rule regex has nested quantifiers (harness must be ReDoS-safe on hostile repos)', () => {
  const nested = new RegExp(String.raw`\((?:\?:)?(?:\[[^\]\n]+\]|\\.|[^()\\|\n])[+*](?:(?:\[[^\]\n]+\]|\\.|[^()\\|\n])[?*])*\)[+*{]`);
  for (const r of ALL) for (const re of [r.pattern, r.taintSink, r.notLine].filter(Boolean)) {
    assert.ok(!nested.test(re.source), `${r.id} has a nested quantifier: ${re.source.slice(0, 80)}`);
  }
});

test('version comparison handles semver, maven and pep440 forms', () => {
  assert.ok(compareVersions('4.17.20', '4.17.21') < 0);
  assert.ok(compareVersions('2.0-beta9', '2.0') < 0);
  assert.ok(compareVersions('2.5.10.1', '2.5.10') > 0);
  assert.ok(compareVersions('1.0.0-rc.1', '1.0.0') < 0);
  assert.ok(inRange('2.14.1', { introduced: '2.0-beta9', fixed: '2.17.1' }));
  assert.ok(!inRange('2.17.1', { introduced: '2.0-beta9', fixed: '2.17.1' }));
  assert.ok(inRange('5.6.1', { versions: ['5.6.1'] }));
});

test('secrets are redacted', () => {
  const r = redact('ghp_' + 'abcdefghijklmnopqrstuvwxyz0123456789');
  assert.ok(!r.includes('abcdefghijkl'));
  assert.ok(r.startsWith('ghp_'));
});

test('comment stripping keeps line numbers and string contents', () => {
  const src = 'a = 1; // eval(x)\n/* exec(y)\n */ b = "http://x//y";';
  const out = stripComments(src, 'javascript');
  assert.equal(out.split('\n').length, 3);
  assert.ok(!out.includes('eval'));
  assert.ok(out.includes('"http://x//y"'));
});

test('string masking keeps interpolations as code', () => {
  assert.equal(maskStrings("q('SELECT name = ?', [id])", 'javascript').includes('name'), false);
  assert.ok(maskStrings('x = `a ${req.query.b} c`', 'javascript').includes('req.query.b'));
  assert.ok(maskStrings('f"SELECT {user}"', 'python').includes('{user}'));
  assert.ok(maskStrings('"WHERE id = $id"', 'php').includes('$id'));
});

test('taint propagates through assignments and stops at casts / allow-list lookups', () => {
  const lines = [
    'const id = req.query.id;',
    'const q = "SELECT * FROM t WHERE id = " + id;',
    'const n = parseInt(req.query.n, 10);',
    'const target = UPSTREAMS[req.query.svc];',
    'const { a, b } = req.body;',
  ];
  const t = analyzeTaint(lines, 'javascript');
  assert.ok(t.tainted.has('id') && t.tainted.has('q') && t.tainted.has('a'));
  assert.ok(!t.tainted.has('n'), 'numeric cast should kill taint');
  assert.ok(!t.tainted.has('target'), 'allow-list lookup should kill taint');
});

test('call argument splitting respects nesting and strings', () => {
  assert.deepEqual(callArgs('f(a, g(b, c), "x,y")', 2).map((s) => s.trim()), ['a', 'g(b, c)', '"x,y"']);
});

test('clone URL / ref validation blocks option and transport injection', () => {
  assert.throws(() => validateUrl('--upload-pack=touch /tmp/pwned'));
  assert.throws(() => validateUrl('file:///etc'));
  assert.throws(() => validateUrl('ext::sh -c touch% /tmp/pwned'));
  assert.throws(() => validateUrl('/local/path'));
  assert.throws(() => validateUrl('http://github.com/a/b'));
  assert.throws(() => validateUrl('git@github.com:a/b.git'));
  assert.equal(validateUrl('https://github.com/a/b'), 'https://github.com/a/b');
  assert.ok(validateUrl('git@github.com:a/b.git', { allowSsh: true }));
  assert.throws(() => validateRef('--output=/tmp/x'));
  assert.throws(() => validateRef('../../etc'));
  assert.equal(validateRef('v1.2.3'), 'v1.2.3');
});

test('quarantine renames agent/IDE auto-load files', () => {
  const d = tmpdir({ 'CLAUDE.md': 'x', 'sub/AGENTS.md': 'y', '.claude/settings.json': '{"hooks":{}}', '.vscode/tasks.json': '{}', 'src/app.js': 'z' });
  const moved = quarantine(d).sort();
  assert.deepEqual(moved, ['.claude/settings.json', '.vscode/tasks.json', 'CLAUDE.md', 'sub/AGENTS.md']);
  assert.ok(fs.existsSync(path.join(d, 'CLAUDE.md.appsec-quarantined')));
  assert.ok(fs.existsSync(path.join(d, 'src/app.js')));
});

test('walker does not follow symlinks out of the repository', async () => {
  const d = tmpdir({ 'app.js': 'const x = 1;\n' });
  const outside = tmpdir({ 'secret.js': "const k = 'AKIA" + 'ABCDEFGHIJKLMNOP' + "';\n" });
  fs.symlinkSync(outside, path.join(d, 'linked'), process.platform === 'win32' ? 'junction' : 'dir');
  const r = await scan(d, {});
  assert.ok(!r.findings.some((f) => f.ruleId === 'SECRET-AWS-001'), 'must not read through symlink');
  assert.ok(r.findings.some((f) => f.ruleId === 'FILE-SYMLINK-001'));
});

test('inline suppressions in the target are not trusted by default', async () => {
  const d = tmpdir({ 'a.js': "// appsec-ignore JS-CODE-001: totally fine\neval(req.query.x);\n" });
  const untrusted = await scan(d, {});
  assert.equal(untrusted.findings.find((f) => f.ruleId === 'JS-CODE-001').status, 'open');
  const trusted = await scan(d, { trustSuppressions: true });
  assert.equal(trusted.findings.find((f) => f.ruleId === 'JS-CODE-001').status, 'suppressed');
});

test('triage validation enforces evidence and confinement; merge + gate', async () => {
  const d = tmpdir({ 'a.js': "const x = req.query.x;\neval(x);\n", 'guard.js': 'module.exports = 1;\n' });
  const r = await scan(d, {});
  const f = r.findings.find((x) => x.ruleId === 'JS-CODE-001');
  assert.ok(f);
  const bad = validateTriage(r, { schema: 'appsec-harness/triage@1', reviewer: 't', verdicts: [{ fingerprint: f.fingerprint, verdict: 'false_positive', rationale: 'looks fine to me honestly' }] });
  assert.equal(bad.ok, false);
  const escape = validateTriage(r, { schema: 'appsec-harness/triage@1', reviewer: 't', verdicts: [{ fingerprint: f.fingerprint, verdict: 'false_positive', rationale: 'guarded by a sanitizer elsewhere', evidence: [{ file: '../../etc/passwd', line: 1 }] }] });
  assert.equal(escape.ok, false);
  const good = { schema: 'appsec-harness/triage@1', reviewer: 't', verdicts: [{ fingerprint: f.fingerprint, verdict: 'false_positive', rationale: 'guard.js:1 rejects every non-numeric value first', evidence: [{ file: 'guard.js', line: 1 }] }] };
  assert.equal(validateTriage(r, good).ok, true);
  assert.equal(gate(r, { failOn: 'high' }).passed, false);
  const merged = mergeTriage(r, good);
  assert.equal(merged.findings.find((x) => x.fingerprint === f.fingerprint).status, 'false_positive');
  assert.equal(gate(merged, { failOn: 'high' }).passed, true);
});

test('HTML report cannot be broken out of by hostile code snippets', async () => {
  const d = tmpdir({ 'x.js': "eval(req.query.a); // </script><script>alert(1)</script>\n" });
  const r = await scan(d, {});
  r.findings[0].snippet = '</script><img src=x onerror=alert(1)>';
  const html = toHtml(r);
  const dataBlock = html.slice(html.indexOf('id="data">'), html.indexOf('</script>', html.indexOf('id="data">')));
  assert.ok(!dataBlock.includes('</script'), 'data block must not contain a closing script tag');
  assert.ok(!dataBlock.includes('<img'), 'angle brackets are escaped');
  assert.match(html, /Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-/);
  assert.ok(!/innerHTML/.test(html.slice(html.lastIndexOf('<script>'))), 'renderer must not use innerHTML');
});

test('SARIF and JUnit outputs are structurally valid', async () => {
  const d = tmpdir({ 'a.py': 'import os\nfrom flask import request\nos.system("ping " + request.args["h"])\n' });
  const r = await scan(d, {});
  const s = toSarif(r);
  assert.equal(s.version, '2.1.0');
  const res = s.runs[0].results[0];
  assert.equal(s.runs[0].tool.driver.rules[res.ruleIndex].id, res.ruleId);
  assert.ok(res.partialFingerprints['appsecFingerprint/v1']);
  assert.ok(s.runs[0].tool.driver.rules[0].properties['security-severity']);
  const x = toJUnit(r, { failOn: 'high' });
  assert.match(x, /^<\?xml/);
  assert.equal((x.match(/<testsuite /g) || []).length, 11, 'one suite per OWASP category plus explicit analysis coverage');
  assert.match(x, /<failure type="PY-CMDI-001"/);
});

test('corpus benchmark passes', async () => {
  const { run } = require('./corpus-runner');
  const origLog = console.log;
  console.log = () => {};
  try { assert.equal(await run({}), 0); } finally { console.log = origLog; }
});
