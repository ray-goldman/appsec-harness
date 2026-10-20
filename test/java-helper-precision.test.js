'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { scan } = require('../src/engine');

async function findings(t, source, extra = {}, options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'appsec-java-helpers-'));
  t.after(() => {
    const resolved = fs.realpathSync(root);
    assert.equal(path.dirname(resolved), fs.realpathSync(os.tmpdir()));
    assert.ok(path.basename(resolved).startsWith('appsec-java-helpers-'));
    fs.rmSync(resolved, { recursive: true, force: true });
  });
  for (const [file, text] of Object.entries({ 'Example.java': source, ...extra })) {
    fs.mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
    fs.writeFileSync(path.join(root, file), text);
  }
  return (await scan(root, { includeTests: true, ...options })).findings.filter(f => f.cwe.includes(89) || f.cwe.includes(78));
}
const query = value => `statement.executeQuery("SELECT name FROM users WHERE name='" + ${value} + "'");`;

test('private constant-return helper resolves at its caller', async t => {
  assert.equal((await findings(t, `class Example {
    private String value() { String answer = "fixed"; return answer; }
    void run() { String selected = value(); ${query('selected')} }
  }`)).length, 0);
});

test('private parameter-dependent helper specializes each call without sharing safe results', async t => {
  const hits = await findings(t, `class Example {
    private String decorate(String value) { return "prefix" + value; }
    void safe() { String selected = decorate("fixed"); ${query('selected')} }
    void unsafe() { String selected = decorate(request.getParameter("x")); ${query('selected')} }
  }`);
  assert.ok(hits.length);
  assert.ok(hits.every(h => h.line === 4));
});

test('private sink parameters require every caller to be safe', async t => {
  for (const unsafe of [false, true]) {
    const hits = await findings(t, `class Example {
      private void consume(String value) { ${query('value')} }
      void first() { consume("fixed"); }
      ${unsafe ? 'void second() { consume(request.getParameter("x")); }' : ''}
    }`);
    assert.equal(hits.length === 0, !unsafe);
  }
});

test('public sink helpers never infer complete callers from the scanned source', async t => {
  assert.ok((await findings(t, `class Example {
    public void consume(String value) { ${query('value')} }
    void run() { consume("fixed"); }
  }`)).length);
});

test('unknown return arm, recursion, overload ambiguity and virtual calls retain findings', async t => {
  for (const methods of [
    'private String value() { if (flag) return "fixed"; return request.getParameter("x"); }',
    'private String value() { return value(); }',
    'private String value() { return "fixed"; } private String value(int x) { return request.getParameter("x"); }',
    'public String value() { return "fixed"; }',
  ]) assert.ok((await findings(t, `class Example { ${methods}
    void run() { String selected = value(); ${query('selected')} }
  }`)).length, methods);
});

test('constant alternatives returned through a static source helper are independent of its guard', async t => {
  const source = `import sample.Commands; class Example {
    void run() { String prefix = Commands.prefix("echo"); Runtime.getRuntime().exec(prefix + "fixed"); }
  }`;
  const helper = `package sample; public class Commands {
    public static String prefix(String verb) {
      String result;
      if (System.getProperty("os.name").contains("Windows")) result = "cmd /c " + verb;
      else result = verb + " ";
      return result;
    }
  }`;
  assert.equal((await findings(t, source, { 'sample/Commands.java': helper })).length, 0);
  assert.ok((await findings(t, source.replace('"echo"', 'request.getParameter("x")'), { 'sample/Commands.java': helper })).length);
});

test('missing and duplicate static source definitions retain findings', async t => {
  const source = `class Example { void run() {
    String selected = sample.Names.value(); ${query('selected')}
  } }`;
  assert.ok((await findings(t, source)).length);
  const helper = 'package sample; public class Names { public static String value() { return "fixed"; } }';
  assert.ok((await findings(t, source, { 'a/Names.java': helper, 'b/Names.java': helper })).length);
});

test('parameter reassignment, method references and mutable returns retain findings', async t => {
  for (const methods of [
    'private String value(String x) { x = request.getParameter("x"); return x; }',
    'private String value(String x) { return field; }',
  ]) assert.ok((await findings(t, `class Example { ${methods}
    void run() { String selected = value("fixed"); ${query('selected')} }
  }`)).length);
  assert.ok((await findings(t, `class Example {
    private void consume(String value) { ${query('value')} }
    void run() { consume("fixed"); Object callback = this::consume; }
  }`)).length);
});

test('a value receiver shadowing an imported class must not select the static helper', async t => {
  assert.ok((await findings(t, `import sample.Names; class Example {
    void run(Other Names) { String selected = Names.value(); ${query('selected')} }
  }`, { 'sample/Names.java': 'package sample; public class Names { public static String value() { return "fixed"; } }',
    'Other.java': 'class Other { public String value() { return request.getParameter("x"); } }' })).length, 'shadowed receiver retains SQL warning');
});

test('unsupported overload declarations and reflection prevent closed helper inference', async t => {
  assert.ok((await findings(t, `class Example {
    private String value() { return "fixed"; }
    private double value(int x) { return 0; }
    void run() { String selected = value(); ${query('selected')} }
  }`)).length, 'unsupported overload retains SQL warning');
  assert.ok((await findings(t, `class Example {
    private void consume(String value) { ${query('value')} }
    void run() { consume("fixed"); getClass().getDeclaredMethod("consume", String.class).invoke(this, request.getParameter("x")); }
  }`)).length, 'reflective callers retain SQL warning');
});

test('private parameter writes cannot create invariant guard facts', async t => {
  assert.ok((await findings(t, `class Example {
    private String value(int flag) {
      if (condition) flag = 1;
      String answer;
      if (flag == 1) answer = "fixed"; else answer = request.getParameter("x");
      return answer;
    }
    void run() { String selected = value(0); ${query('selected')} }
  }`)).length);
});

test('skipped Java definitions cannot establish a complete static source index', async t => {
  const source = `class Example { void run() { String selected = sample.Names.value(); ${query('selected')} } }`;
  assert.ok((await findings(t, source, {
    'a/Names.java': 'package sample; public class Names { public static String value() { return "fixed"; } }',
    'b/Names.java': 'package sample; public class Names { public static String value() { return request.getParameter("x"); } }' + ' '.repeat(600),
  }, { maxFileSize: 512 })).length, 'incomplete Java source inventory');
});

test('helper expansion depth exhaustion retains findings', async t => {
  const methods = Array.from({ length: 7 }, (_, i) => `private String value${i}() { return ${i === 6 ? '"fixed"' : `value${i + 1}()`}; }`).join('\n');
  assert.ok((await findings(t, `class Example { ${methods}
    void run() { String selected = value0(); ${query('selected')} }
  }`)).length, 'depth bound');
});

test('reflective invocation prevents private caller closure even without a named reference', async t => {
  assert.ok((await findings(t, `class Example {
    private void consume(String value) { ${query('value')} }
    void safe() { consume("fixed"); }
    void unsafe() throws Exception {
      java.lang.reflect.Method m = getClass().getDeclaredMethods()[0];
      m.setAccessible(true);
      m.invoke(this, request.getParameter("x"));
    }
  }`)).length);
});

test('HTML encoding cannot sanitize SQL or shell arguments', async t => {
  for (const sink of [query('clean'), 'Runtime.getRuntime().exec(clean);']) {
    const hits = await findings(t, `class Example {
      void run() {
        String input = request.getParameter("value");
        String clean = org.owasp.encoder.Encode.forHtml(input);
        ${sink}
      }
    }`);
    assert.ok(hits.length, sink);
  }
});

test('an inherited value receiver cannot select an imported static helper', async t => {
  for (const inheritance of ['extends', 'implements']) {
    const hits = await findings(t, `import sample.Names; class Example ${inheritance} Base {
      void run() { String selected = Names.value(); ${query('selected')} }
    }`, {
      'Base.java': inheritance === 'extends' ? 'class Base { protected Other Names; }'
        : 'interface Base { Other Names = new Other(); }',
      'Other.java': 'class Other { public String value() { return request.getParameter("x"); } }',
      'sample/Names.java': 'package sample; public class Names { public static String value() { return "fixed"; } }',
    });
    assert.ok(hits.length);
  }
});

test('inherited overloads cannot borrow a local summary for a different argument type', async t => {
  for (const crossFile of [false, true]) {
    const hits = await findings(t, crossFile
      ? `class Example { void run() { String selected = Names.value(1); ${query('selected')} } }`
      : `class Example extends Base { private String value(String x) { return "fixed"; }
        void run() { String selected = value(1); ${query('selected')} } }`, {
      'Names.java': 'class Names extends Base { static String value(String x) { return "fixed"; } }',
      'Base.java': 'class Base { static String value(int x) { return System.getenv("VALUE"); } }',
    });
    assert.ok(hits.length);
  }
});

test('comma-separated fields can shadow an imported class owner', async t => {
  const hits = await findings(t, `import sample.Names; class Example {
    Other first, Names;
    void run() { String selected = Names.value(); ${query('selected')} }
  }`, {
    'Other.java': 'class Other { public String value() { return System.getenv("VALUE"); } }',
    'sample/Names.java': 'package sample; public class Names { public static String value() { return "fixed"; } }',
  });
  assert.ok(hits.length);
});
