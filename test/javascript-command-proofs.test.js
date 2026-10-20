'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { scan } = require('../src/engine');

async function warnings(t, files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kayfabe-js-command-'));
  t.after(() => {
    const real = fs.realpathSync(root);
    assert.equal(path.dirname(real), fs.realpathSync(os.tmpdir()));
    assert.ok(path.basename(real).startsWith('kayfabe-js-command-'));
    fs.rmSync(real, { recursive: true, force: true });
  });
  for (const [name, text] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, name)), { recursive: true });
    fs.writeFileSync(path.join(root, name), text);
  }
  return (await scan(root, { includeTests: true })).findings.filter(f => f.ruleId === 'JS-CMDI-001');
}
const helper = `function allowed(host) {
  return typeof host === 'string' && host.length > 0 && host.length <= 253 && !/[^a-z0-9.-]/i.test(host);
}
module.exports = { allowed };
`;
const caller = `const { exec } = require('node:child_process');
const { allowed } = require('./hostname.js');
function handler(req) {
  const host = req.query.host;
  if (!allowed(host)) return;
  exec('ping -c1 ' + host);
}
`;
const config = `module.exports = { REPORT_CMD: 'ls -l', BACKUP_DIR: '/var/backups' };\n`;
const configCaller = `const { exec } = require('node:child_process');
const cfg = require('./config.js');
function handler(req) {
  exec(cfg.REPORT_CMD + ' ' + cfg.BACKUP_DIR);
}
`;

test('typed hostname helper dominates a direct command call', async t => {
  assert.equal((await warnings(t, { 'routes.js': caller, 'hostname.js': helper })).length, 0);
});
test('closed local literal config exports remove a constant-command candidate', async t => {
  assert.equal((await warnings(t, { 'routes.js': configCaller, 'config.js': config })).length, 0);
});
test('coercing, permissive, stateful or non-dominating hostname guards retain warnings', async t => {
  for (const [route, check] of [
    [caller, helper.replace("typeof host === 'string' && ", '')],
    [caller, helper.replace('/[^a-z0-9.-]/i', '/[^a-z0-9.;-]/i')],
    [caller, helper.replace('/i.test', '/ig.test')],
    [caller, "function allowed(host) { return /^[a-z0-9.-]{1,253}$/i.test(String(host)); }\nmodule.exports = { allowed };"],
    [caller.replace('if (!allowed(host)) return;', 'if (!allowed(host)) {}'), helper],
    [caller.replace("  exec('ping", "  const other = req.query.other;\n  exec('ping"), helper],
    [caller.replace(" + host);", " + host + req.query.other);"), helper],
    [caller.replace('ping -c1 ', 'sh -c '), helper],
    [caller.replace('ping -c1 ', 'cmd /c '), helper],
  ]) assert.ok((await warnings(t, { 'routes.js': route, 'hostname.js': check })).length);
});
test('mutable, ambiguous or unresolved configuration ownership retains warnings', async t => {
  for (const files of [
    { 'routes.js': configCaller, 'config.js': config + "module.exports.REPORT_CMD = userValue;\n" },
    { 'routes.js': configCaller + "require('./missing.js');\n", 'config.js': config },
    { 'routes.js': configCaller.replace('./config.js', './config'), 'config.js': config },
    { 'routes.js': configCaller, 'config.js': "module.exports = { REPORT_CMD: process.env.CMD, BACKUP_DIR: '/tmp' };" },
    { 'routes.js': configCaller.replace(" + ' ' + cfg.BACKUP_DIR", " + req.query.path"), 'config.js': config },
    { 'routes.js': configCaller, 'config.js': config, 'other.js': "const cfg = require('./config.js'); cfg.REPORT_CMD = value;" },
    { 'routes.js': configCaller.replace('function handler(req)', 'function handler(req, cfg)'), 'config.js': config },
    { 'routes.js': configCaller + 'function update(req) { ({cmd: cfg.REPORT_CMD} = req.query); }', 'config.js': config },
    { 'routes.js': configCaller + 'function update(req) { [cfg.REPORT_CMD] = req.query.values; }', 'config.js': config },
  ]) assert.ok((await warnings(t, files)).length);
});
