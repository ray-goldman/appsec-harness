'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { scan } = require('../src/engine');

async function sql(t, body) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'appsec-java-branches-'));
  t.after(() => {
    const resolved = fs.realpathSync(directory);
    assert.equal(path.dirname(resolved), fs.realpathSync(os.tmpdir()));
    assert.ok(path.basename(resolved).startsWith('appsec-java-branches-'));
    fs.rmSync(resolved, { recursive: true, force: true });
  });
  fs.writeFileSync(path.join(directory, 'Example.java'), `class Example {
    void run(HttpServletRequest request) {
      String input = request.getParameter("value");
      ${body}
    }
  }`);
  return (await scan(directory, { includeTests: true })).findings.filter(f => f.cwe.includes(89));
}

const sink = `String query = "SELECT * FROM users WHERE name='" + selected + "'";
statement.executeQuery("SELECT * FROM users WHERE name='" + selected + "'");`;

test('Java arithmetic and literal edge cases cannot select the wrong safe branch', async t => {
  for (const [label, condition] of [
    ['integer overflow', '2147483647 + 1 > 0'],
    ['integer division truncates toward zero', '-5 / 2 != -2'],
    ['octal literals are not decimal', '010 == 10'],
    ['long literals retain unsupported uncertainty', '9223372036854775807L + 1L > 0L'],
    ['remainder retains Java sign', '-5 % 2 != -1'],
  ]) {
    const hits = await sql(t, `String selected;
      if (${condition}) selected = "constant"; else selected = input;
      ${sink}`);
    assert.ok(hits.length, label);
  }
});

test('String reference equality is not string value equality', async t => {
  const hits = await sql(t, `String first = "same";
    String second = first + "";
    String selected;
    if (first == second) selected = "constant"; else selected = input;
    ${sink}`);
  assert.ok(hits.length);
});

test('changing loop guards cannot borrow their initial constant value', async t => {
  const hits = await sql(t, `int mode = 0;
    while (more) {
      String selected;
      if (mode == 0) selected = "constant"; else selected = input;
      ${sink}
      mode = 1;
    }`);
  assert.ok(hits.length);
});

test('switch fallthrough cannot hide a later request assignment', async t => {
  const hits = await sql(t, `int mode = 1;
    String selected = "initial";
    switch (mode) {
      case 1: selected = "constant";
      case 2: selected = input; break;
      default: selected = "other";
    }
    ${sink}`);
  assert.ok(hits.length);
});

test('a break in a nested loop does not terminate the surrounding switch', async t => {
  const hits = await sql(t, `int mode = 1;
    String selected = "initial";
    switch (mode) {
      case 1: for (int i = 0; i < 1; i++) { break; }
      case 2: selected = input; break;
      default: selected = "other";
    }
    ${sink}`);
  assert.ok(hits.length);
});

test('dangling else binds to the nearest if', async t => {
  const hits = await sql(t, `String selected = input;
    if (true)
      if (false) selected = "constant";
      else selected = input;
    ${sink}`);
  assert.ok(hits.length);
});

test('a safe SQL expression on a line cannot hide a second unsafe expression', async t => {
  const hits = await sql(t, `String selected = "constant";
    String safe = "SELECT '" + selected + "'"; String unsafe = "SELECT '" + input + "'";
    statement.executeQuery(unsafe);`);
  assert.ok(hits.some(f => f.ruleId === 'JAVA-SQLI-002'));
});

test('unknown boolean calls and helper returns retain all possible branches', async t => {
  const hits = await sql(t, `String selected;
    if (configuration()) selected = "constant"; else selected = input;
    ${sink}`);
  assert.ok(hits.length);
});

test('constant branch suppression generalizes beyond benchmark arithmetic', async t => {
  for (const declaration of [
    'int limit = 13; String selected; if ((limit * 3) - 2 == 37) selected = "known"; else selected = input;',
    'int limit = 9; String selected = limit / 2 == 4 ? "known" : input;',
  ]) {
    assert.equal((await sql(t, `${declaration}\n${sink}`)).length, 0);
  }
});

test('a proved branch silences both the SQL assembly and indirect execution findings', async t => {
  const hits = await sql(t, `int limit = 13;
    String selected;
    if (limit == 13) {
      selected = "known";
    } else {
      selected = input;
    }
    String query = "SELECT * FROM users WHERE name='" + selected + "'";
    statement.executeQuery(query);`);
  assert.equal(hits.length, 0);
});
