'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { scan } = require('../src/engine');

async function sqlFindings(t, files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kayfabe-js-ownership-'));
  t.after(() => {
    const real = fs.realpathSync(root);
    assert.equal(path.dirname(real), fs.realpathSync(os.tmpdir()));
    assert.ok(path.basename(real).startsWith('kayfabe-js-ownership-'));
    fs.rmSync(real, { recursive: true, force: true });
  });
  for (const [name, text] of Object.entries(files)) {
    const file = path.join(root, name);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, text);
  }
  return (await scan(root, { includeTests: true })).findings.filter(f => /^JS-SQLI/.test(f.ruleId));
}

const numeric = `function other(req) { const id = req.query.id; }
function handler(req) {
  const id = Number(read(req, 'id'));
  db.query("SELECT * FROM records WHERE id = " + id);
}`;
const source = 'const read = (req, key) => req.query[key];\nmodule.exports = { read };\n';

test('computed request reads and regex classes do not invalidate numeric SQL', async t => {
  assert.equal((await sqlFindings(t, {
    'routes.js': 'const { read } = require("./input");\n' + numeric,
    'input.js': source + 'function hostname(value) { return /^[a-z0-9.-]+$/i.test(String(value)); }\n',
  })).length, 0);
});

test('computed lookup data can reach a modeled command API without becoming executable JavaScript', async t => {
  assert.equal((await sqlFindings(t, {
    'routes.js': `const { read } = require("./input");
const { exec } = require("child_process");
const commands = { status: "uptime" };
function command(req) {
  const cmd = commands[read(req, "which")];
  exec(cmd);
}
` + numeric,
    'input.js': source,
  })).length, 0);
});

test('ordinary local classes and unrelated parameter names preserve numeric proof', async t => {
  assert.equal((await sqlFindings(t, {
    'routes.js': `const { read } = require("./input");
class Search { constructor(req) { this.term = req.query.q; } where() { return "name = " + this.term; } }
function convert(s) { return String(s); }
function route(req) { const s = new Search(req); db.query(s.where()); }
function label(req) { return convert(req.query["label"]); }
` + numeric,
    'input.js': source,
  })).filter(f => f.line > 6).length, 0);
});

test('computed constructor calls, aliases, callbacks and property writes retain warnings', async t => {
  for (const patch of [
    '[]["constructor"]["constructor"]("Number = x => x")();',
    'const make = []["constructor"]["constructor"]; make("Number = x => x")();',
    'const make = []["constructor"]["constructor"]; const box = { make }; box.make("Number = x => x")();',
    'function invoke(fn) { fn("Number = x => x")(); }\ninvoke([]["constructor"]["constructor"]);',
    'unknown([]["constructor"]["constructor"]);',
    'const target = {}; target["Number"] = x => x;',
    'const make = []["constructor"]["constructor"]; new make("Number = x => x");',
    'function Make() { return []["constructor"]["constructor"]; } new (new (new Make())("Number = x => x"))();',
    'for (const F of [[]["constructor"]["constructor"]]) new (new F("Number = x => x"))();',
    'class Make { constructor() { return []["constructor"]["constructor"]; } } new Make();',
    'class A { get() { return { query: []["constructor"]["constructor"] }; } } const box = new A().get(); function run() {} run = box.query("Number = x => x"); run();',
    'function make(){ return {query: []["constructor"]["constructor"]}; } const box = {get: make}.get(); class A { constructor(){ this.query = box.query("Number = x => x"); } } new A().query();',
    'function make(){ return {query: []["constructor"]["constructor"]}; } module.exports = {get: make}; const box = module.exports.get(); class A { constructor(){ this.query = box.query("Number = x => x"); } } new A().query();',
    'function factory(){ return () => ({query: []["constructor"]["constructor"]}); } const box = {get: factory()}.get(); class A { constructor(){ this.query = box.query("Number = x => x"); } } new A().query();',
    'function make(x = {query: []["constructor"]["constructor"]}){ return x; } const box = make(); class A { constructor(){ this.query = box.query("Number = x => x"); } } new A().query();',
    'const {constructor: {constructor: query}} = []; const box = {query}; class A { constructor(){ this.query = box.query("Number = x => x"); } } new A().query();',
  ]) assert.ok((await sqlFindings(t, {
    'routes.js': 'const { read } = require("./input");\n' + patch + '\n' + numeric,
    'input.js': source,
  })).length, patch);
});

test('dynamic loaders and explicit code-execution APIs keep the proof unknown', async t => {
  for (const patch of [
    'const vm = require("node:vm"); vm.runInThisContext("Number = x => x");',
    'const name = "vm"; const vm = require(name); vm.runInThisContext("Number = x => x");',
    'const fs = require("fs"); fs.writeFileSync("./patch.js", "Number = x => x"); require("./patch");',
    'const marker=[]; const loader={query:require}; const {runInThisContext:query}=loader.query("vm"); const box={query}; box.query("Number = x => x");',
    'const marker=[]; const fs=require("fs"); const {writeFileSync:query}=fs; const writer={query}; writer.query("./patch.js", "Number = x => x"); require("./patch");',
    'const marker=[]; const fs=require("fs"); const writer={query:fs.writeFileSync}; writer.query("./patch.js", "Number = x => x"); require("./patch");',
    'const marker=[]; const writer={query:require("fs").writeFileSync}; writer.query("./patch.js", "Number = x => x"); require("./patch");',
    'const marker=[]; const loader={query:process.getBuiltinModule}; const {runInThisContext:query}=loader.query("vm"); const box={query}; box.query("Number = x => x");',
  ]) assert.ok((await sqlFindings(t, {
    'routes.js': 'const { read } = require("./input");\n' + patch + '\n' + numeric,
    'input.js': source,
  })).length, patch);
});

test('local object and class methods returning computed capabilities fail closed', () => {
  const { computedDataOnly } = require('../src/js-computed');
  for (const raw of [
    'class A { get() { return { query: []["constructor"]["constructor"] }; } } const box = new A().get();',
    'const a = { get() { return { query: []["constructor"]["constructor"] }; } }; const box = a.get();',
  ]) assert.equal(computedDataOnly({ sources: [{ lang: 'javascript', file: 'input.js', raw }] }), false);
});

test('vendored parser bytes match provenance and unsupported input fails closed', () => {
  const crypto = require('node:crypto');
  const provenance = require('../src/parsers/acorn.provenance.json');
  for (const [entry, file] of [['package/dist/acorn.js', 'acorn.js'], ['package/LICENSE', 'ACORN-LICENSE.txt']]) {
    assert.equal(crypto.createHash('sha256').update(fs.readFileSync(path.join(__dirname, '../src/parsers', file))).digest('hex'), provenance.files[entry]);
  }
  const { computedDataOnly } = require('../src/js-computed');
  const project = raw => ({ sources: [{ lang: 'javascript', file: 'input.js', raw }] });
  assert.equal(computedDataOnly(project('invalid !!! javascript')), false);
  assert.equal(computedDataOnly(project('function inspect(value) { return arguments; }')), false);
  assert.equal(computedDataOnly(project('function keep(a, b) { return b; } keep(...values);')), false);
  assert.equal(computedDataOnly(project(' '.repeat(250001))), false);
  const Module = require('node:module'), original = Module._load;
  try {
    Module._load = function (id, ...args) {
      if (id === './parsers/acorn') throw Error('Parser unavailable');
      return original.call(this, id, ...args);
    };
    assert.equal(computedDataOnly(project('const n = 1;')), false);
  } finally { Module._load = original; }
});
