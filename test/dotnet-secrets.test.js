'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { scan } = require('../src/engine');
const { buildTriageRequest } = require('../src/triage');
const { toSarif } = require('../src/report/sarif');
const { toHtml } = require('../src/report/html');
const { toJUnit } = require('../src/report/junit');
const { toMarkdown } = require('../src/report/markdown');
async function scanned(t, files, opts = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kayfabe-dotnet-secret-'));
  t.after(() => { assert.equal(path.dirname(fs.realpathSync(root)), fs.realpathSync(os.tmpdir())); assert.ok(path.basename(root).startsWith('kayfabe-dotnet-secret-')); fs.rmSync(root, { recursive: true, force: true }); });
  for (const [name, text] of Object.entries(files)) fs.writeFileSync(path.join(root, name), text);
  return scan(root, { includeTests: true, ...opts });
}
const password = () => crypto.randomBytes(18).toString('base64url');
const connection = p => `Server=db.internal;Database=hr;User Id=service;Password=${p};`;
const has = (r, id) => r.findings.some(f => f.ruleId === id);
test('literal C# and JSON connection passwords are detected without an entropy threshold', async t => {
  for (const p of [password(), 'a' + 'b']) {
    const r = await scanned(t, { 'Store.cs': `const string ConnStr = ${JSON.stringify(connection(p))};`, 'appsettings.json': JSON.stringify({ ConnectionStrings: { Primary: connection(p) } }) });
    assert.ok(has(r, 'SECRET-DOTNET-CONN-001'));
    assert.equal(r.findings.filter(f => f.ruleId === 'SECRET-DOTNET-CONN-001').length, 2);
  }
});
test('quoted delimiters, aliases and C# verbatim connection literals are recognized', async t => {
  const p = password() + ';tail';
  for (const value of [`Data Source=db;UID=svc;PWD='${p}';`, `Server=db;User ID=svc;Password="${p}";`]) {
    const r = await scanned(t, { 'Store.cs': 'var c = @"' + value.replaceAll('"', '""') + '";' });
    assert.ok(has(r, 'SECRET-DOTNET-CONN-001'));
  }
  const r = await scanned(t, { 'web.config': `<connectionStrings><add name="Main" connectionString="Server=db;User Id=svc;Password=&quot;${p}&quot;;" /></connectionStrings>` });
  assert.ok(has(r, 'SECRET-DOTNET-CONN-001'));
});
test('passwordless authentication, placeholders and unrelated fields remain quiet', async t => {
  const values = ['Server=db;Database=hr;Integrated Security=true;', 'Server=db;Authentication=Active Directory Managed Identity;', 'Server=db;User Id=svc;Password=;', 'Server=db;User Id=svc;Password=${DB_PASSWORD};', 'Server=db;User Id=svc;Password={0};', 'Server=db;User Id=svc;Password=__PASSWORD__;', 'Server=db;User Id=svc;Password=your_password;', 'Password=ordinary prose;', 'Server=db;Application Name=Password=anything;'];
  for (const value of values) assert.ok(!has(await scanned(t, { 'Store.cs': `var c = ${JSON.stringify(value)};` }), 'SECRET-DOTNET-CONN-001'));
  assert.ok(!has(await scanned(t, { 'Store.cs': 'var c = $"Server=db;User Id=svc;Password={credential};";' }), 'SECRET-DOTNET-CONN-001'));
});
test('literal ASP.NET machine keys are detected, generated keys and placeholders are not', async t => {
  const key = crypto.randomBytes(32).toString('hex');
  const r = await scanned(t, { 'web.config': `<configuration><system.web><machineKey\n validationKey="${key}"\n decryptionKey="${crypto.randomBytes(32).toString('hex')}" />\n</system.web></configuration>` });
  assert.ok(has(r, 'SECRET-ASPNET-MACHINEKEY-001'));
  for (const value of ['AutoGenerate,IsolateApps', '__MACHINE_KEY__', '0'.repeat(64)]) {
    assert.ok(!has(await scanned(t, { 'web.config': `<machineKey validationKey="${value}" decryptionKey="${value}" />` }), 'SECRET-ASPNET-MACHINEKEY-001'));
  }
});
function assertAbsent(outputs, markers) {
  for (const output of outputs) for (const marker of markers) assert.equal(output.includes(marker), false, 'sensitive marker must not be serialized');
}
function outputs(r) { return [JSON.stringify(r), JSON.stringify(toSarif(r)), toHtml(r), toJUnit(r), toMarkdown(r), JSON.stringify(buildTriageRequest(r))]; }
test('connection passwords never enter reports, neighbouring triage context or truncated snippets', async t => {
  const p = password(), second = password();
  const longPrefix = ' '.repeat(10) + 'const string ' + 'x'.repeat(150) + ' = ';
  const code = `${longPrefix}${JSON.stringify(connection(p) + 'Pwd=' + second + ';')};\nvar a = new BinaryFormatter().Deserialize(Request.Body);\n`;
  const r = await scanned(t, { 'Store.cs': code });
  assert.ok(has(r, 'SECRET-DOTNET-CONN-001'));
  assert.ok(has(r, 'CS-DESER-001'));
  assertAbsent(outputs(r), [p, p.slice(0, 8), second, second.slice(0, 8)]);
});
test('multiple secrets on a finding line and multiline machine keys are fully omitted', async t => {
  const a = password(), b = password();
  const key = crypto.randomBytes(32).toString('hex');
  const r = await scanned(t, { 'Store.cs': `var c = ${JSON.stringify(connection(a))}; var d = ${JSON.stringify(connection(b))}; new BinaryFormatter();`, 'web.config': `<machineKey\n validationKey="${key}"\n decryptionKey="${crypto.randomBytes(32).toString('hex')}" />` });
  assert.ok(has(r, 'SECRET-DOTNET-CONN-001'));
  assert.ok(has(r, 'SECRET-ASPNET-MACHINEKEY-001'));
  assertAbsent(outputs(r), [a, b, key, key.slice(0, 8)]);
});
test('existing generic secrets are redacted before truncation and from neighbouring triage context', async t => {
  const p = password();
  const r = await scanned(t, { 'Store.cs': ' '.repeat(5) + 'string ' + 'a'.repeat(190) + `Password = "${p}";\nnew BinaryFormatter();` });
  assert.ok(has(r, 'SECRET-GENERIC-001'));
  assertAbsent(outputs(r), [p, p.slice(0, 8)]);
});
test('suppression comments cannot leak credentials into metadata or SARIF justifications', async t => {
  const p = password();
  for (const trustSuppressions of [false, true]) {
    const r = await scanned(t, { 'Store.cs': `// appsec-ignore: SECRET-DOTNET-CONN-001 - ${connection(p)}\nvar c = ${JSON.stringify(connection(p))};\nnew BinaryFormatter();` }, { trustSuppressions });
    assert.ok(has(r, 'SECRET-DOTNET-CONN-001'));
    assertAbsent(outputs(r), [p, p.slice(0, 8)]);
  }
});
test('private key bodies are excluded from adjacent triage context', async t => {
  const body = crypto.randomBytes(48).toString('base64');
  const r = await scanned(t, { 'Store.cs': `/* -----BEGIN ${'RSA PRIVATE KEY'}-----\n${body}\n-----END ${'RSA PRIVATE KEY'}----- */\nnew BinaryFormatter();` });
  assert.ok(has(r, 'SECRET-PK-001'));
  assertAbsent(outputs(r), [body, body.slice(0, 10)]);
});
test('machineKey lookalike names and attribute text are not key configuration', async t => {
  const key = crypto.randomBytes(32).toString('hex');
  for (const text of [`<machineKey-backup validationKey="${key}" />`, `<machineKey data-validationKey="${key}" />`, `<machineKey x:validationKey="${key}" />`, `<machineKey description="validationKey='${key}'" />`]) {
    assert.ok(!has(await scanned(t, { 'web.config': text }), 'SECRET-ASPNET-MACHINEKEY-001'));
  }
});
