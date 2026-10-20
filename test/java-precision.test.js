'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { scan } = require('../src/engine');

async function findings(t, source, ruleId) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'appsec-java-precision-'));
  t.after(() => {
    const resolved = fs.realpathSync(root);
    assert.equal(path.dirname(resolved), fs.realpathSync(os.tmpdir()));
    assert.ok(path.basename(resolved).startsWith('appsec-java-precision-'));
    fs.rmSync(resolved, { recursive: true, force: true });
  });
  fs.writeFileSync(path.join(root, 'Example.java'), source);
  return (await scan(root, { includeTests: true })).findings.filter(f => f.ruleId === ruleId);
}

test('constant SQL in a neighboring method does not inherit request data', async (t) => {
  const hits = await findings(t, `class Example {
    void unsafe(HttpServletRequest request) {
      String data = request.getParameter("name");
      statement.executeQuery("SELECT * FROM users WHERE name = '" + data + "'");
    }
    void constant() {
      String data = "known";
      statement.executeQuery("SELECT * FROM users WHERE name = '" + data + "'");
    }
  }`, 'JAVA-SQLI-001');
  assert.deepEqual(hits.map(h => h.line), [4]);
});

test('constant command alternatives stay quiet without trusting unknown commands', async (t) => {
  const hits = await findings(t, `class Example {
    void constant(boolean windows) {
      String command;
      if (windows) { command = "cmd /c echo "; }
      else { command = "/bin/echo "; }
      String value = "hello";
      Runtime.getRuntime().exec(command + value);
    }
    void unknown() {
      String command = configuration();
      Runtime.getRuntime().exec(command + " hello");
    }
  }`, 'JAVA-CMDI-001');
  assert.deepEqual(hits.map(h => h.line), [11]);
});

test('constant split elements can be used in SQL without injection', async (t) => {
  const hits = await findings(t, `class Example {
    void constant() {
      String data;
      data = "alice-bob";
      String names[] = data.split("-");
      for (int i = 0; i < names.length; i++) {
        statement.addBatch("UPDATE users SET active=1 WHERE name='" + names[i] + "'");
      }
    }
  }`, 'JAVA-SQLI-001');
  assert.equal(hits.length, 0);
});

test('a constant redirect is isolated from another method with request input', async (t) => {
  const hits = await findings(t, `class Example {
    void unsafe(HttpServletRequest request) {
      String target = request.getParameter("url");
      response.sendRedirect(target);
    }
    void constant() {
      String target = "/home";
      response.sendRedirect(target);
    }
  }`, 'JAVA-REDIRECT-001');
  assert.deepEqual(hits.map(h => h.line), [4]);
});

test('branch-dependent request data and later loop writes stay findings', async (t) => {
  for (const body of [
    'String data = "fixed"; if (condition) { data = request.getParameter("x"); }',
    'String data; if (condition) { data = "fixed"; } else { data = request.getParameter("x"); }',
  ]) {
    const hits = await findings(t, `class Example { void run() {
      ${body}
      statement.executeQuery("SELECT * FROM users WHERE name='" + data + "'");
    } }`, 'JAVA-SQLI-001');
    assert.equal(hits.length, 1);
  }
  const loop = await findings(t, `class Example { void run() {
    String data = "fixed";
    while (condition) {
      statement.executeQuery("SELECT * FROM users WHERE name='" + data + "'");
      data = request.getParameter("x");
    }
  } }`, 'JAVA-SQLI-001');
  assert.equal(loop.length, 1);
});

test('mutable or escaping arrays are not treated as constant values', async (t) => {
  for (const change of ['names[0] = request.getParameter("x");', 'mutate(names);', 'String[] alias = names; alias[0] = request.getParameter("x");']) {
    const hits = await findings(t, `class Example {
      void run() {
        String[] names = "alice-bob".split("-");
        ${change}
        statement.addBatch("SELECT * FROM users WHERE name='" + names[0] + "'");
      }
    }`, 'JAVA-SQLI-001');
    assert.equal(hits.length, 1, change);
  }
});

test('fields and unknown expressions retain warnings', async (t) => {
  const hits = await findings(t, `class Example {
    String data = "default";
    void run() {
      statement.executeQuery("SELECT * FROM users WHERE name='" + data + "'");
    }
  }`, 'JAVA-SQLI-001');
  assert.equal(hits.length, 1);
});

test('constant suppression does not hide another dynamic call on the same line', async (t) => {
  const hits = await findings(t, `class Example {
    void run() {
      String safe = "constant";
      String data = request.getParameter("x");
      statement.executeQuery("SELECT '" + safe + "'"); statement.executeQuery("SELECT '" + data + "'");
    }
  }`, 'JAVA-SQLI-001');
  assert.equal(hits.length, 1);
});

test('weak cryptography remains a finding even with a constant argument', async (t) => {
  const hits = await findings(t, 'class Example { void run() { Cipher.getInstance("AES"); } }', 'JAVA-CRYPTO-001');
  assert.equal(hits.length, 1);
});

test('block shadows and declarations after a sink cannot prove field values constant', async (t) => {
  for (const body of [
    `if (condition) { String data = "fixed"; }
     statement.executeQuery("SELECT '" + data + "'");`,
    `statement.executeQuery("SELECT '" + data + "'");
     String data = "fixed";`,
  ]) {
    const hits = await findings(t, `class Example {
      String data = request.getParameter("x");
      void run() { ${body} }
    }`, 'JAVA-SQLI-001');
    assert.equal(hits.length, 1);
  }
});

test('an alias evaluated before a local declaration still reads the field', async (t) => {
  const hits = await findings(t, `class Example {
    String data = request.getParameter("x");
    void run() {
      String alias = data;
      String data = "fixed";
      statement.executeQuery("SELECT '" + alias + "'");
    }
  }`, 'JAVA-SQLI-001');
  assert.equal(hits.length, 1);
});

test('repeated alias expansion exhausts a bounded proof and retains the warning', async (t) => {
  const declarations = ['String a0 = "x";'];
  for (let i = 1; i <= 32; i++) declarations.push(`String a${i} = a${i - 1} + a${i - 1};`);
  const hits = await findings(t, `class Example { void run() {
    ${declarations.join('\n')}
    statement.executeQuery("SELECT '" + a32 + "'");
  } }`, 'JAVA-SQLI-001');
  assert.equal(hits.length, 1);
});

test('nested block String arrays and commands can be proved constant', async (t) => {
  const source = `class Example { void run() {
    if (condition) {
      String names[] = "alice-bob".split("-");
      for (int i = 0; i < names.length; i++) {
        statement.addBatch("SELECT '" + names[i] + "'");
      }
      { String command = "echo hello"; Runtime.getRuntime().exec(command); }
    }
  } }`;
  assert.equal((await findings(t, source, 'JAVA-SQLI-001')).length, 0);
  assert.equal((await findings(t, source, 'JAVA-CMDI-001')).length, 0);
});

test('disjoint sibling locals resolve their own initializers and writes', async (t) => {
  const source = `class Example { void run() {
    { String data = request.getParameter("x");
      statement.executeQuery("SELECT '" + data + "'"); }
    { String data = "fixed";
      String alias = data;
      statement.executeQuery("SELECT '" + alias + "'"); }
    { String data = "other"; data = "known";
      statement.executeQuery("SELECT '" + data + "'"); }
  } }`;
  assert.deepEqual((await findings(t, source, 'JAVA-SQLI-001')).map(h => h.line), [3]);
});

test('nested shadows cannot prove fields outside their declaration scope or before declaration', async (t) => {
  for (const body of [
    '{ String data = "fixed"; } statement.executeQuery("SELECT \'" + data + "\'");',
    '{ statement.executeQuery("SELECT \'" + data + "\'"); String data = "fixed"; }',
    '{ String alias = data; String data = "fixed"; statement.executeQuery("SELECT \'" + alias + "\'"); }',
    '{ String data = "fixed"; } { statement.executeQuery("SELECT \'" + data + "\'"); }',
  ]) {
    const source = `class Example { String data = request.getParameter("x"); void run() { ${body} } }`;
    assert.equal((await findings(t, source, 'JAVA-SQLI-001')).length, 1, body);
  }
});

test('all writes resolve the scope of the assignment including later loop writes', async (t) => {
  for (const body of [
    'String data = "fixed"; { data = request.getParameter("x"); } statement.executeQuery("SELECT \'" + data + "\'");',
    'String data = "fixed"; while (condition) { statement.executeQuery("SELECT \'" + data + "\'"); { data = request.getParameter("x"); } }',
    'String data = "fixed"; { String next = request.getParameter("x"); data = next; } statement.executeQuery("SELECT \'" + data + "\'");',
  ]) {
    assert.equal((await findings(t, `class Example { void run() { ${body} } }`, 'JAVA-SQLI-001')).length, 1, body);
  }
  const source = `class Example { void run() {
    String data = "fixed";
    while (condition) {
      statement.executeQuery("SELECT '" + data + "'");
      { String next = "known"; data = next; }
    }
  } }`;
  assert.equal((await findings(t, source, 'JAVA-SQLI-001')).length, 0);
});

test('array escapes and mutations across scopes retain warnings', async (t) => {
  for (const change of [
    '{ mutate(names); }',
    '{ String[] alias = names; alias[0] = request.getParameter("x"); }',
    '{ names[0] = request.getParameter("x"); }',
  ]) {
    const source = `class Example { void run() {
      { String[] names = "alice-bob".split("-");
        ${change}
        statement.executeQuery("SELECT '" + names[0] + "'");
      }
    } }`;
    assert.equal((await findings(t, source, 'JAVA-SQLI-001')).length, 1, change);
  }
});

test('local and anonymous classes retain warnings', async (t) => {
  for (const declaration of [
    'class Local { String data = request.getParameter("x"); }',
    'enum Local { VALUE; }',
    'Object value = new Object() { String data = request.getParameter("x"); };',
    'Object value = new java.lang.Object() { String data = request.getParameter("x"); };',
    'Object value = new Container<String>() { String data = request.getParameter("x"); };',
  ]) {
    const source = `class Example { void run() {
      String data = "fixed";
      ${declaration}
      statement.executeQuery("SELECT '" + data + "'");
    } }`;
    assert.equal((await findings(t, source, 'JAVA-SQLI-001')).length, 1, declaration);
  }
});

test('unsupported loop headers and resources cannot leak constants into surrounding scopes', async (t) => {
  for (const body of [
    'for (String data = "fixed"; condition;) {} statement.executeQuery("SELECT \'" + data + "\'");',
    'try (String data = "fixed") {} statement.executeQuery("SELECT \'" + data + "\'");',
    '{ String data = "fixed"; } for (String data : inputs) { statement.executeQuery("SELECT \'" + data + "\'"); }',
  ]) {
    const source = `class Example { String data = request.getParameter("x"); void run() { ${body} } }`;
    assert.equal((await findings(t, source, 'JAVA-SQLI-001')).length, 1, body);
  }
});

test('writes to a field before a later local declaration do not change the local binding', async (t) => {
  const source = `class Example {
    String data;
    void run() {
      data = request.getParameter("x");
      { String data = "fixed"; statement.executeQuery("SELECT '" + data + "'"); }
    }
  }`;
  assert.equal((await findings(t, source, 'JAVA-SQLI-001')).length, 0);
});

test('constant arithmetic branches and ternaries suppress every SQL warning including assembly', async (t) => {
  for (const select of [
    'int num = 86; String data; if ((7 * 42) - num > 200) { data = "safe"; } else { data = request.getParameter("x"); }',
    'int num = 106; String data = ((7 * 42) - num > 200) ? request.getParameter("x") : "safe";',
    'boolean yes = true; String data; if (yes) data = "safe"; else data = request.getParameter("x");',
    'String guess = "ABC"; char target = guess.charAt(1); String data; switch (target) { case \'A\': data = request.getParameter("x"); break; case \'B\': data = "safe"; break; default: data = request.getParameter("y"); }',
  ]) {
    const source = `class Example { void run() {
      ${select}
      String sql = "SELECT * FROM users WHERE name='" + data + "'";
      statement.executeQuery("SELECT '" + data + "'");
    } }`;
    const hits = [...await findings(t, source, 'JAVA-SQLI-001'), ...await findings(t, source, 'JAVA-SQLI-002')];
    assert.equal(hits.length, 0, select);
  }
});

test('unsafe selected branches and unsupported Java semantics retain SQL findings', async (t) => {
  for (const setup of [
    'int num = 106;', 'int num = 2147483647 + 1;', 'int num = 1 / 0;',
    'long num = 86;', 'double num = 86;', 'int num = 0106;',
    'int num = 86; num++;', 'int num = 86; ++num;',
    'int num = 86; while (condition) { num = 106; }',
  ]) {
    const condition = setup.includes('0106') ? 'num == 106' : setup.includes('++') ? 'num == 86' : '(7 * 42) - num > 200';
    const source = `class Example { void run() {
      ${setup}
      String data; if (${condition}) data = "safe"; else data = request.getParameter("x");
      statement.executeQuery("SELECT '" + data + "'");
    } }`;
    assert.ok((await findings(t, source, 'JAVA-SQLI-001')).length, setup);
  }
});

test('switch fallthrough, unknown labels and string reference comparisons preserve unsafe writes', async (t) => {
  for (const select of [
    'int target = 1; String data; switch (target) { case 1: data = "safe"; case 2: data = request.getParameter("x"); break; default: data = "other"; }',
    'int target = 1; String data; switch (target) { case other: data = request.getParameter("x"); break; default: data = "safe"; }',
    'String a = "x"; String b = "x"; String data; if (a == b) data = "safe"; else data = request.getParameter("x");',
    'boolean yes = true; String data; if (yes) if (unknown) data = "safe"; else data = request.getParameter("x"); else data = "safe";',
  ]) {
    const source = `class Example { void run() { ${select}
      statement.executeQuery("SELECT '" + data + "'");
    } }`;
    assert.ok((await findings(t, source, 'JAVA-SQLI-001')).length, select);
  }
});

test('constant SQL assembly on a mixed line never hides an unsafe assembly or sink', async (t) => {
  for (const extra of [
    'String dynamic = "SELECT name FROM users WHERE id=" + input;',
    'statement.executeQuery("SELECT name FROM users WHERE id=" + input);',
  ]) {
    const source = `class Example { void run() {
      String data = "fixed";
      String input = request.getParameter("x");
      String sql = "SELECT name FROM users WHERE id=" + data; ${extra}
    } }`;
    assert.ok((await findings(t, source, 'JAVA-SQLI-001')).length + (await findings(t, source, 'JAVA-SQLI-002')).length, extra);
  }
});

test('a conditional terminal break does not end a switch on every path', async (t) => {
  const source = `class Example { void run() {
    int target = 1; String data;
    switch (target) { case 1: data = "safe"; if (unknown) break; case 2: data = request.getParameter("x"); break; default: data = "safe"; }
    statement.executeQuery("SELECT '" + data + "'");
  } }`;
  assert.ok((await findings(t, source, 'JAVA-SQLI-001')).length);
});

test('deep or oversized Java expressions retain warnings without exhausting the scanner', async (t) => {
  for (const expression of ['('.repeat(200) + 'true' + ')'.repeat(200), 'true && '.repeat(700) + 'true']) {
    const source = `class Example { void run() {
      String data; if (${expression}) data = "safe"; else data = request.getParameter("x");
      statement.executeQuery("SELECT '" + data + "'");
    } }`;
    assert.ok((await findings(t, source, 'JAVA-SQLI-001')).length);
  }
});

test('unsupported Java syntax retains SQL findings instead of throwing', async (t) => {
  for (const unsupported of ['Runnable action = () -> work();', 'String other = "\\u0061";', 'String block = """text""";']) {
    const source = `class Example { void run() {
      ${unsupported}
      String data = request.getParameter("x");
      String sql = "SELECT name FROM users WHERE id=" + data;
    } }`;
    assert.ok((await findings(t, source, 'JAVA-SQLI-002')).length);
  }
});

test('ternary numeric promotion cannot misclassify a character as text', async (t) => {
  for (const condition of ['true ? \'A\' : 65536', 'true ? \'A\' : number', 'true ? 1 : floating()']) {
    const source = `class Example { void run() {
      int number = 65; String data;
      if (("" + (${condition})).charAt(0) == 'A') data = "safe"; else data = request.getParameter("x");
      statement.executeQuery("SELECT '" + data + "'");
    } }`;
    assert.ok((await findings(t, source, 'JAVA-SQLI-001')).length, condition);
  }
});

test('constant branches before opaque try handlers retain their independent proof', async (t) => {
  for (const selection of [
    'int n = 1; String data; if (n == 1) data = "safe"; else data = request.getParameter("x");',
    'int n = 1; String data; switch(n) { case 1: data = "safe"; break; default: data = request.getParameter("x"); }',
  ]) {
    const source = `class Example { void run() {
      ${selection}
      try { statement.executeQuery("SELECT '" + data + "'"); } catch (Exception e) { log(e); } finally { cleanup(); }
    } }`;
    assert.equal((await findings(t, source, 'JAVA-SQLI-001')).length, 0);
  }
});

test('unknown branches and writes in finally cannot prove an earlier condition invariant', async (t) => {
  for (const later of ['n = 2;', 'data = request.getParameter("later");']) {
    const source = `class Example { void run() {
      int n = 1; String data;
      if (n == 1) data = "safe"; else data = request.getParameter("x");
      while (condition) {
        try { statement.executeQuery("SELECT '" + data + "'"); } finally { ${later} }
      }
    } }`;
    assert.ok((await findings(t, source, 'JAVA-SQLI-001')).length);
  }
});

test('parenthesized variable updates cannot leave a stale constant condition', async (t) => {
  for (const mutation of ['(num)++;', '++(num);', '(num)--;', '--(num);', '((num))++;', '(num) += 1;', '(num) = 87;']) {
    const source = `class Example { void run() {
      int num = 86; ${mutation}
      String data; if (num == 86) data = "safe"; else data = request.getParameter("x");
      statement.executeQuery("SELECT '" + data + "'");
    } }`;
    assert.ok((await findings(t, source, 'JAVA-SQLI-001')).length, mutation);
  }
});

test('a safe SQL first argument cannot prove another SQL fragment in the same call', async (t) => {
  const source = `class Example { void run() {
    String input = request.getParameter("x");
    String fixed = "known";
    jdbcTemplate.query("SELECT name FROM users WHERE id=" + fixed, "SELECT name FROM users WHERE id=" + input);
  } }`;
  assert.ok((await findings(t, source, 'JAVA-SQLI-002')).length);
});

test('parentheses around array call arguments do not hide escaping mutable elements', async (t) => {
  for (const escape of ['int size = mutate(names).length;', 'String value = mutate(names)[0];', 'int size = mutate((names)).length;']) {
    const source = `class Example { void run() {
      String[] names = "alice-bob".split("-");
      ${escape}
      statement.executeQuery("SELECT '" + names[0] + "'");
    } }`;
    assert.ok((await findings(t, source, 'JAVA-SQLI-001')).length, escape);
  }
});

test('wrapped and nested-index array writes remain unsafe in every lexical block', async (t) => {
  for (const nested of [false, true]) {
    for (const write of [
      '(names[0]) = input;', '((names[0])) = input;',
      'names[indexes[0]] = input;', 'names[(true ? 0 : indexes[0])] = input;',
      '(names[indexes[0]]) += input;',
    ]) {
      const source = `class Example { void run() {
        ${nested ? '{' : ''}
        String input = request.getParameter("x");
        String[] names = "alice-bob".split("-");
        ${write}
        statement.executeQuery("SELECT '" + names[0] + "'");
        ${nested ? '}' : ''}
      } }`;
      assert.ok((await findings(t, source, 'JAVA-SQLI-001')).length, `${nested}: ${write}`);
    }
  }
});

test('simple array reads still prove constant elements safe in nested blocks', async (t) => {
  const source = `class Example { void run() {
    { String[] names = "alice-bob".split("-");
      String value = names[index];
      statement.executeQuery("SELECT '" + value + "'");
    }
  } }`;
  assert.equal((await findings(t, source, 'JAVA-SQLI-001')).length, 0);
});

test('repeated-u and comment-hidden Java Unicode escapes disable constant suppression', async (t) => {
  for (const mutation of [
    String.raw`\uu0064ata = request.getParameter("x");`,
    String.raw`\uuuu0064ata = request.getParameter("x");`,
    String.raw`// \uu000a data = request.getParameter("x");`,
    String.raw`// \u000a data = request.getParameter("x");`,
  ]) {
    const source = `class Example { void run() {
      String data = "safe";
      ${mutation}
      statement.executeQuery("SELECT '" + data + "'");
    } }`;
    assert.ok((await findings(t, source, 'JAVA-SQLI-001')).length, mutation);
  }
});
