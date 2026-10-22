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
  assert.equal(computedDataOnly(project('function update(req) { ({value: target.field} = req.query); }')), false);
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

async function domFindings(t, source, name = 'client.js') {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kayfabe-js-dom-'));
  t.after(() => {
    const real = fs.realpathSync(root);
    assert.equal(path.dirname(real), fs.realpathSync(os.tmpdir()));
    assert.ok(path.basename(real).startsWith('kayfabe-js-dom-'));
    fs.rmSync(real, { recursive: true, force: true });
  });
  fs.writeFileSync(path.join(root, name), source);
  return (await scan(root, { includeTests: true })).findings.filter(f => f.ruleId === 'JS-XSS-001');
}

test('DOM literal proof removes quoted attributes and bounded constant expression noise', async t => {
  for (const source of [
    `panel.innerHTML = '<span class="ready">Ready</span>';`,
    `panel.innerHTML = '<span class="ready">Ready</span>';\r\n`,
    'panel.outerHTML = `<span class="ready">${ready ? "Ready" : "Waiting"}</span>`;',
    'panel.innerHTML = `<b>${3 + 4}</b>`;',
    'panel.innerHTML = `<b>${"ready" || "waiting"}</b>`;',
    'panel.innerHTML = `<b>${null ?? "waiting"}</b>`;',
    `panel.insertAdjacentHTML('beforeend', '<span class="ready">Ready</span>');`,
    `document.write('<span class="ready">Ready</span>');`,
    `document.writeln('<b class="ready">Ready</b>', '<i class="ready">Now</i>');`,
    '$("#panel").html(`<b>${ready ? "Ready" : "Waiting"}</b>`);',
    `panel.innerHTML = '<b class="ready">A</b>'; other.outerHTML = '<b class="ready">B</b>';`,
  ]) assert.equal((await domFindings(t, source)).length, 0, source);
});

test('DOM proof retains dynamic twins and every unsafe sink sharing a line', async t => {
  for (const source of [
    'panel.innerHTML = `<b>${ready ? location.hash : "Waiting"}</b>`;',
    'panel.innerHTML = `<b>${location.hash || "waiting"}</b>`;',
    'panel.innerHTML = `<b>${({toString(){ return location.hash; }})}</b>`;',
    `panel.innerHTML = '<b class="ready">Ready</b>'; other.innerHTML = location.hash;`,
    `panel.innerHTML = '<b class="ready">Ready</b>'; document.write(location.hash);`,
    `panel.innerHTML = '<b class="ready">Ready</b>'; $("#other").append(location.hash);`,
    `panel.innerHTML = '<b class="ready">Ready</b>'; other.innerHTML =\n location.hash;`,
    `panel.innerHTML = '<b class="ready">Ready</b>' +\n location.hash;`,
    `panel.innerHTML += '<b class="ready">Ready</b>';`,
    `document.write('<b class="ready">Ready</b>', location.hash);`,
    `const html = '<b class="ready">Ready</b>'; panel.innerHTML = html;`,
    'panel.innerHTML = commandEscape(location.hash);',
    'panel.innerHTML = encodeURIComponent(location.hash);',
    `panel.innerHTML = '<b class="ready">Ready</b>';\ninvalid !!! javascript`,
  ]) assert.ok((await domFindings(t, source)).length, source);
});

test('DOM literal proof fails closed for parser limits and unsupported file syntax', async t => {
  const source = `panel.innerHTML = '<b class="ready">Ready</b>';`;
  assert.ok((await domFindings(t, source + '\n' + ' '.repeat(200001))).length);
  assert.ok((await domFindings(t, source + '\n' + '0;'.repeat(25000))).length);
  assert.ok((await domFindings(t, source + '\n' + '['.repeat(170) + '0' + ']'.repeat(170) + ';')).length);
  assert.ok((await domFindings(t, source + '\nconst element = <Panel/>;', 'client.jsx')).length);
  assert.ok((await domFindings(t, source + '\nconst n: number = 1;', 'client.ts')).length);
  const Module = require('node:module'), original = Module._load;
  try {
    Module._load = function (id, ...args) {
      if (id === './parsers/acorn') throw Error('Parser unavailable');
      return original.call(this, id, ...args);
    };
    assert.ok((await domFindings(t, source)).length);
  } finally { Module._load = original; }
});

test('a fixed DOM sink cannot hide computed or unknown member sinks on its line', async t => {
  for (const later of [
    `other['innerHTML'] = location.hash;`,
    `document['write'](location.hash);`,
    `other['insertAdjacentHTML']('beforeend', location.hash);`,
    `other[field] = location.hash;`,
    `other[method](location.hash);`,
  ]) {
    const source = `panel.innerHTML = '<b class="ready">Ready</b>'; ` + later;
    assert.ok((await domFindings(t, source)).length, source);
  }
});

test('a fixed DOM sink cannot hide write calls through document member chains', async t => {
  for (const sink of ['window.document.write', 'self.document.writeln']) {
    const source = `panel.innerHTML = '<b class="ready">Ready</b>'; ${sink}(location.hash);`;
    assert.ok((await domFindings(t, source)).length, source);
  }
});

test('DOM literal proof fails closed on line terminators the regex engine does not split', async t => {
  for (const separator of ['\r', '\u2028', '\u2029']) {
    const source = `panel.innerHTML = '<b class="ready">Ready</b>';${separator}other.innerHTML = location.hash;`;
    assert.ok((await domFindings(t, source)).length, JSON.stringify(separator));
  }
});

test('a fixed DOM sink cannot hide writes through assignment patterns or loop targets', async t => {
  for (const later of [
    '({x: other.innerHTML = location.hash} = {});',
    '[other.innerHTML = location.hash] = [];',
    `({x: other['innerHTML'] = location.hash} = {});`,
    '({x: other[field] = location.hash} = {});',
    '({x: other.innerHTML} = input);',
    '[other.innerHTML] = inputs;',
    'for (other.innerHTML of inputs) {}',
    'for (other[field] in input) {}',
    'for ({x: other.innerHTML} of inputs) {}',
  ]) {
    const source = `panel.innerHTML = '<b class="ready">Ready</b>'; ` + later;
    assert.ok((await domFindings(t, source)).length, source);
  }
});
