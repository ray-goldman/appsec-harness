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
