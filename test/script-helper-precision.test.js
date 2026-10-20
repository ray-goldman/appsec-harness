'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { scan } = require('../src/engine');

async function findings(t, files, rule) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kayfabe-script-helpers-'));
  t.after(() => {
    const real = fs.realpathSync(root);
    assert.equal(path.dirname(real), fs.realpathSync(os.tmpdir()));
    assert.ok(path.basename(real).startsWith('kayfabe-script-helpers-'));
    fs.rmSync(real, { recursive: true, force: true });
  });
  for (const [name, text] of Object.entries(files)) {
    const file = path.join(root, name);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, text);
  }
  return (await scan(root, { includeTests: true })).findings.filter(f => rule.test(f.ruleId));
}
const js = (conversion, before = '', after = '') => `${before}
function handler(req, res) {
  const id = ${conversion};
  ${after}
  db.query("SELECT * FROM records WHERE id = " + id);
}`;
const py = (conversion, before = '', after = '') => `${before}
def handler():
    n = ${conversion}
    ${after}
    cursor.execute("SELECT * FROM records WHERE id = %d" % n)
`;
const guardHelper = 'import re\n\ndef allowed(value):\n    return re.fullmatch(r"[A-Za-z0-9.-]{1,253}", value) is not None\n';
const guardCaller = `import checks as h
import subprocess
from flask import request
def handler():
    host = request.args.get("host")
    if not h.allowed(host):
        return "bad", 400
    return subprocess.check_output("ping -c1 " + host, shell=True)
`;

test('numeric SQL conversions retain function scope despite taint elsewhere', async t => {
  assert.equal((await findings(t, { 'routes.js': js('Number(req.query.id)', 'function other(req) { const id = req.query.id; }') }, /^JS-SQLI/)).length, 0);
  assert.equal((await findings(t, { 'views.py': py('int(request.args["id"])', 'def other():\n    n = request.args["id"]\n') }, /^PY-SQLI/)).length, 0);
});

test('local source helpers can return numeric values without trusting their names', async t => {
  assert.equal((await findings(t, {
    'routes.js': js('toId(req.query.id)', 'const { toId } = require("./numbers");'),
    'numbers.js': 'function toId(value) { return Number(value); }\nmodule.exports = { toId };\n',
  }, /^JS-SQLI/)).length, 0);
  assert.equal((await findings(t, {
    'views.py': py('h.to_id(request.args["id"])', 'import numbers_local as h'),
    'numbers_local.py': 'def to_id(value):\n    return int(value)\n',
  }, /^PY-SQLI/)).length, 0);
});

test('a source-resolved Python fullmatch guard dominates the command', async t => {
  assert.equal((await findings(t, { 'views.py': guardCaller, 'checks.py': guardHelper }, /^PY-CMDI/)).length, 0);
  assert.equal((await findings(t, {
    'views.py': guardCaller.replace('host = request.args.get("host")', 'host = h.arg("host")'),
    'checks.py': guardHelper + '\nfrom flask import request\ndef arg(name):\n    """Request string source."""\n    return request.args.get(name, "")\n',
  }, /^PY-CMDI/)).length, 0);
});

test('trim-only helpers, shadowed conversions and reassignment retain SQL warnings', async t => {
  for (const files of [
    { 'routes.js': js('Number(req.query.id)', 'const Number = value => value;') },
    { 'routes.js': js('toId(req.query.id)', 'const { toId } = require("./numbers");'), 'numbers.js': 'function toId(value) { return value.trim(); }\nmodule.exports = { toId };' },
    { 'routes.js': js('Number(req.query.id)', '', 'db.query("SELECT * FROM records WHERE name = " + req.query.name);') },
    { 'views.py': py('int(request.args["id"])', 'def int(value):\n    return value\n') },
    { 'views.py': py('int(request.args["id"])', '', 'n = request.args["id"]') },
    { 'views.py': py('h.to_id(request.args["id"])', 'import numbers_local as h'), 'numbers_local.py': 'def to_id(value):\n    return value.strip()\n' },
  ]) assert.ok((await findings(t, files, /^(JS|PY)-SQLI/)).length, JSON.stringify(files));
});

test('non-dominating, permissive, mutated or ambiguous guards retain command warnings', async t => {
  for (const files of [
    { 'views.py': guardCaller.replace('return "bad", 400', 'print("bad")'), 'checks.py': guardHelper },
    { 'views.py': guardCaller.replace('    return subprocess', '    host = request.args["other"]\n    return subprocess'), 'checks.py': guardHelper },
    { 'views.py': guardCaller, 'checks.py': guardHelper.replace('re.fullmatch', 're.search') },
    { 'views.py': guardCaller, 'checks.py': guardHelper.replace('[A-Za-z0-9.-]', '.*') },
    { 'views.py': guardCaller.replace('def handler():', 'h.allowed = lambda x: True\ndef handler():'), 'checks.py': guardHelper },
    { 'views.py': guardCaller, 'checks.py': guardHelper, 're.py': 'def fullmatch(pattern, value):\n    return True\n' },
    { 'pkg/views.py': guardCaller, 'pkg/checks.py': guardHelper, 'checks.py': guardHelper },
  ]) assert.ok((await findings(t, files, /^PY-CMDI/)).length, JSON.stringify(files));
});

test('POSIX quoting without an explicit shell is not a portable shell proof', async t => {
  assert.ok((await findings(t, { 'views.py': 'import shlex\nimport subprocess\ndef run():\n    host = request.args["host"]\n    clean = shlex.quote(host)\n    return subprocess.check_output("ping " + clean, shell=True)\n' }, /^PY-CMDI/)).length);
});

test('namespace mutation, duplicate definitions and expression side effects fail closed', async t => {
  for (const files of [
    { 'views.py': guardCaller, 'checks.py': guardHelper + '\ndef allowed(value, extra=None):\n    return True\n' },
    { 'views.py': guardCaller.replace('def handler():', 'h.allowed: object = lambda value: True\ndef handler():'), 'checks.py': guardHelper },
    { 'views.py': guardCaller.replace('def handler():', 'h.allowed, other = (lambda value: True), None\ndef handler():'), 'checks.py': guardHelper },
    { 'views.py': guardCaller.replace('def handler():', '(h.allowed) = lambda value: True\ndef handler():'), 'checks.py': guardHelper },
    { 'views.py': guardCaller.replace('return subprocess.check_output', 'return mutate() or subprocess.check_output'), 'checks.py': guardHelper },
    { 'views.py': guardCaller, 'checks.py': '"""' + guardHelper + '"""\ndef allowed(x, y=None):\n    return True\n' },
    { 'views.py': guardCaller.replace('    host =', '    global host\n    host ='), 'checks.py': guardHelper },
    { 'views.py': py('int(request.args["id"])').replace('    n =', '    global n\n    n =') },
  ]) assert.ok((await findings(t, files, /^PY-(?:CMDI|SQLI)/)).length, JSON.stringify(files));
});

test('loader replacement and whitespace-obscured regex patches retain warnings', async t => {
  assert.ok((await findings(t, {
    'routes.js': js('toId(req.query.id)', 'function require(x) { return injected; }\nconst { toId } = require("./numbers");'),
    'numbers.js': 'function toId(value) { return Number(value); }\nmodule.exports = { toId };\n',
  }, /^JS-SQLI/)).length);
  for (const patch of [
    'import re as r\nr . fullmatch = lambda p, v: True\n',
    'import re as r\nr.fullmatch, unused = (lambda p, v: True), None\n',
    'import re as r\npatch(r)\n',
  ]) assert.ok((await findings(t, { 'views.py': guardCaller, 'checks.py': guardHelper, 'patch.py': patch }, /^PY-CMDI/)).length, patch);
});

test('cross-file JavaScript builtin replacement invalidates numeric proofs', async t => {
  for (const extension of ['js', 'cjs', 'mjs', 'ts', 'jsx', 'tsx', 'JS', 'PY', 'mts', 'cts', 'vue', 'svelte']) {
    assert.ok((await findings(t, {
      'routes.js': js('Number(req.query.id)', `require("./patch.${extension}");\nfunction other(req) { const id = req.query.id; }`),
      ['patch.' + extension]: 'Number = value => value;\n',
    }, /^JS-SQLI/)).length, extension);
  }
});

test('multiline decorators cannot lend the original validator body', async t => {
  assert.ok((await findings(t, { 'views.py': guardCaller,
    'checks.py': guardHelper.replace('def allowed', '@(\n    lambda f: lambda v: True\n)\ndef allowed'),
  }, /^PY-CMDI/)).length);
});

test('string subclasses with overloaded concatenation retain command warnings', async t => {
  const subclass = 'class Host(str):\n    def __radd__(self, other):\n        return self.payload\n\ndef wrap(value):\n    host = Host("localhost")\n    host.payload = value\n    return host\n';
  assert.ok((await findings(t, {
    'views.py': guardCaller.replace('def handler():', subclass + '\ndef handler():').replace('host = request.args.get("host")', 'host = wrap(request.args.get("host"))'),
    'checks.py': guardHelper,
  }, /^PY-CMDI/)).length);
});

test('indirect global this mutation retains JavaScript SQL warnings', async t => {
  for (const patch of [
    'function patch() { this["Number"] = value => value; }\npatch();',
    'function patch() { const alias = this; alias["Num" + "ber"] = value => value; }\npatch();',
    'global["Num" + "ber"] = value => value;',
    'window["Number"] = value => value;',
  ]) assert.ok((await findings(t, {
    'routes.js': js('Number(req.query.id)', patch + '\nfunction other(req) { const id = req.query.id; }'),
  }, /^JS-SQLI/)).length, patch);
});

test('normalized Python identifiers do not borrow ASCII binding proofs', async t => {
  assert.ok((await findings(t, { 'views.py': guardCaller,
    'checks.py': guardHelper.replace('def allowed', 'class Fake:\n    def fullmatch(self, pattern, value):\n        return True\nｒｅ = Fake()\ndef allowed'),
  }, /^PY-CMDI/)).length);
});

test('computed constructors and cached export mutation retain JavaScript warnings', async t => {
  assert.ok((await findings(t, {
    'routes.js': js('Number(req.query.id)', '[]["constructor"]["constructor"]("Number = value => value")();\nfunction other(req) { const id = req.query.id; }'),
  }, /^JS-SQLI/)).length);
  assert.ok((await findings(t, {
    'routes.js': js('toId(req.query.id)', 'require("./patch");\nconst { toId } = require("./numbers");'),
    'numbers.js': 'function toId(value) { return Number(value); }\nmodule.exports = { toId };\n',
    'patch.js': 'const mod = require("./numbers");\nmod.toId = value => value;\n',
  }, /^JS-SQLI/)).length);
  for (const specifier of ['../numbers', '/app/numbers', 'numbers-package', './missing', './num\\x62ers']) {
    assert.ok((await findings(t, {
      'routes.js': js('toId(req.query.id)', 'require("./lib/patch");\nconst { toId } = require("./numbers");'),
      'numbers.js': 'function toId(value) { return Number(value); }\nmodule.exports = { toId };\n',
      'lib/patch.js': `const mod = require("${specifier}");\nmod.toId = value => value;\n`,
    }, /^JS-SQLI/)).length, specifier);
  }
});
