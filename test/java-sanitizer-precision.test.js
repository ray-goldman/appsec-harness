'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { scan } = require('../src/engine');
const escape = value => `org.springframework.web.util.HtmlUtils.htmlEscape(${value})`;
const print = value => `response.getWriter().print(${value});`;

async function findings(t, body, methods = '', extra = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'appsec-java-sanitizers-'));
  t.after(() => {
    const resolved = fs.realpathSync(root);
    assert.equal(path.dirname(resolved), fs.realpathSync(os.tmpdir()));
    assert.ok(path.basename(resolved).startsWith('appsec-java-sanitizers-'));
    fs.rmSync(resolved, { recursive: true, force: true });
  });
  const source = `import javax.servlet.http.*;
  public class Example extends HttpServlet {
    ${methods}
    protected void doPost(HttpServletRequest request, HttpServletResponse response) {
      String input = request.getParameter("value");
      ${body}
    }
  }`;
  for (const [file, text] of Object.entries({ 'Example.java': source, ...extra })) {
    fs.mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
    fs.writeFileSync(path.join(root, file), text);
  }
  return (await scan(root, { includeTests: true })).findings.filter(f => f.ruleId === 'JAVA-XSS-001');
}

test('HTML text encoding survives aliases and private helper returns', async t => {
  for (const expression of [escape('input'), 'encode(input)']) {
    const hits = await findings(t, `String clean = ${expression};
      String alias = clean;
      ${print('alias')}`, `private String encode(String value) { return ${escape('value')}; }`);
    assert.equal(hits.length, 0);
  }
});

test('HTML encoding only protects every dynamic value in a known text context', async t => {
  assert.equal((await findings(t, `String clean = ${escape('input')};
    ${print('"<p>" + clean + "</p>"')}`)).length, 0);
  for (const expression of ['clean + input', '"<script>let x=\\\'" + clean + "\\\';</script>"',
    '"<a href=\\\"" + clean + "\\\">link</a>"']) {
    assert.ok((await findings(t, `String clean = ${escape('input')}; ${print(expression)}`)).length, expression);
  }
});

test('earlier script output and unknown response aliases retain context uncertainty', async t => {
  for (const before of [print('"<script>let x=\\\'"'), 'helper(response);']) {
    assert.ok((await findings(t, `${before}
      String clean = ${escape('input')};
      ${print('clean')}`)).length, before);
  }
});

test('reassignment, partial branches and decoding remove encoding guarantees', async t => {
  for (const change of [
    'clean = input;',
    'if (condition) clean = input;',
    'clean = org.springframework.web.util.HtmlUtils.htmlUnescape(clean);',
  ]) assert.ok((await findings(t, `String clean = ${escape('input')};
    ${change}
    ${print('clean')}`)).length, change);
});

test('a sanitizer elsewhere on the same line cannot hide a second unsafe sink', async t => {
  assert.ok((await findings(t, `${print(escape('input'))} ${print('input')}`)).length, 'second raw sink');
});

test('custom safe-looking names and shadowed library classes retain warnings', async t => {
  assert.ok((await findings(t, `String value = safeHtml(input);
    ${print('value')}`, 'private String safeHtml(String input) { return input; }')).length, 'custom sanitizer');
  assert.ok((await findings(t, `${print(escape('input'))}`, '', {
    'HtmlUtils.java': 'package org.springframework.web.util; public class HtmlUtils { public static String htmlEscape(String x) { return x; } }',
  })).length, 'shadowed library');
});

test('printf checks substitutions rather than treating an encoded format as sufficient', async t => {
  assert.equal((await findings(t, `String clean = ${escape('input')};
    response.getWriter().printf(java.util.Locale.US, "<p>%s</p>", clean);`)).length, 0);
  assert.ok((await findings(t, `response.getWriter().printf(${escape('"%s"')}, input);`)).length, 'raw substitution');
});

test('constant XSS output cannot inherit another method taint', async t => {
  assert.equal((await findings(t, `String value = "fixed";
    ${print('value')}`, 'void other(HttpServletRequest request) { String value = request.getParameter("x"); }')).length, 0);
});

test('a response helper needs an established HTML stream context', async t => {
  const ambiguous = `void echo(HttpServletRequest request, HttpServletResponse response) {
    ${print(escape('request.getParameter("x")'))}
  }`;
  assert.ok((await findings(t, '', ambiguous)).length, 'unknown caller output context');
  const fresh = ambiguous.replace('{\n', '{\n response.resetBuffer(); response.setContentType("text/html;charset=UTF-8");\n');
  assert.equal((await findings(t, '', fresh)).length, 0);
});

test('shadowed servlet types do not establish library output contracts', async t => {
  assert.ok((await findings(t, print(escape('input')), '', {
    'javax/servlet/http/HttpServletResponse.java': 'package javax.servlet.http; public class HttpServletResponse {}',
  })).length, 'shadowed servlet contract');
});

test('conditional output cannot close a script context unconditionally', async t => {
  for (const guard of ['if (false)', 'for (; condition; )', 'while (condition)']) {
    assert.ok((await findings(t, `${print('"<script>"')}
      ${guard} ${print('"</script>"')}
      ${print(escape('input'))}`)).length, guard);
  }
});

test('a proved response sink cannot suppress an unproved writer on the same line', async t => {
  assert.ok((await findings(t, `java.io.PrintWriter out = response.getWriter();
    out.print(input); ${print('"fixed"')}`)).length);
});

test('HTML facts cannot hide structural markup in aliases, helpers or parameters', async t => {
  for (const expression of [`"<script>" + ${escape('input')} + "</script>"`, 'wrap(input)', 'join("<script>", input)']) {
    assert.ok((await findings(t, `String clean = ${expression}; ${print('clean')}`,
      `private String wrap(String value) { return "<script>" + ${escape('value')} + "</script>"; }
       private String join(String prefix, String value) { return prefix + ${escape('value')}; }`)).length, expression);
  }
});

test('writer integer overload and different response receivers retain their own context', async t => {
  for (const before of [
    'response.getWriter().write(60); response.getWriter().write("script>");',
    'other.response.getWriter().print("<script>"); response.getWriter().print("</script>");',
  ]) {
    const target = before.startsWith('other') ? 'other.response.getWriter().print' : 'response.getWriter().print';
    const hits = await findings(t, `${before} ${target}(${escape('input')});`);
    assert.ok(hits.length, before);
  }
});

test('explicit servlet imports and direct character copies preserve HTML text encoding', async t => {
  const explicit = 'import javax.servlet.http.HttpServlet; import javax.servlet.http.HttpServletRequest; import javax.servlet.http.HttpServletResponse;';
  const source = `${explicit}
    public class ServletExample extends HttpServlet {
      protected void doPost(HttpServletRequest request, HttpServletResponse response) {
        String input = request.getParameter("value");
        String clean = ${escape('input')};
        response.getWriter().write(clean.toCharArray());
      }
    }`;
  assert.equal((await findings(t, '', '', { 'ServletExample.java': source })).length, 0);
});

test('println newline can complete an HTML tag name before a following attribute', async t => {
  const hits = await findings(t, `response.getWriter().println("<script");
    ${print('"x>"')}
    ${print(escape('input'))}`);
  assert.ok(hits.length);
});

test('repeated output cannot borrow the first iteration HTML context', async t => {
  const hits = await findings(t, `while (condition) {
    ${print(escape('input') + ' + "<script>"')}
  }`);
  assert.ok(hits.length);
});

test('unsupported browser comment and raw-text states retain warnings', async t => {
  for (const prefix of ['<!--><script><!-- -->', "<noscript><p title='</noscript><script>'>", '<script><!--<script></script>', "<p a=b'><script>'>"]) {
    // Split --> so the source-level lambda fallback cannot mask this test.
    const expression = prefix.split('-->').map(JSON.stringify).join(' + "--" + ">" + ');
    const hits = await findings(t, `${print(expression)} ${print(escape('input'))}`);
    assert.ok(hits.length, prefix);
  }
});

test('skipped source directories cannot establish encoder ownership', async t => {
  const hits = await findings(t, print(escape('input')), '', {
    'build/HtmlUtils.java': 'package org.springframework.web.util; public class HtmlUtils { public static String htmlEscape(String x) { return x; } }',
  });
  assert.ok(hits.length);
});

test('immutable formatting arrays render each indexed substitution in HTML text', async t => {
  for (const declaration of ['Object[] parts = {"a", clean};', 'String[] parts = {"a", clean};',
    'final Object[] parts = {"a", clean};']) {
    const hits = await findings(t, `String clean = ${escape('input')};
      ${declaration}
      response.getWriter().printf(java.util.Locale.US, "<p>%1$s and %2$s %% %n</p>", parts);`);
    assert.equal(hits.length, 0, declaration);
  }
});

test('formatting arrays cannot hide raw elements, mutation, aliases or object callbacks', async t => {
  for (const [declaration, change] of [
    ['Object[] parts = {"a", input};', ''],
    ['Object[] parts = {"a", clean};', 'parts[1] = input;'],
    ['Object[] parts = {"a", clean};', '(parts)[1] = input;'],
    ['Object[] parts = {"a", clean};', 'parts = new Object[] {"a", input};'],
    ['Object[] parts = {"a", clean};', 'Object[] alias = parts; alias[1] = input;'],
    ['Object[] parts = {"a", clean};', 'mutate(parts, input);'],
    ['Object[] parts = {new Dangerous(), clean};', ''],
    ['Object[] parts = {"a", input};', `input = ${escape('input')};`],
  ]) {
    assert.ok((await findings(t, `String clean = ${escape('input')};
      ${declaration} ${change}
      response.getWriter().printf("%1$s %2$s", parts);`)).length, declaration + change);
  }
});

test('formatting arrays preserve output structure, scope and unsupported contexts', async t => {
  for (const [prefix, declaration, format, suffix] of [
    ['', 'Object[] parts = {"<script>", clean};', '%1$s %2$s', ''],
    ['', 'Object[] parts = {"a", clean};', '<a href="%2$s">', ''],
    ['response.getWriter().print("<script>");', 'Object[] parts = {"a", clean};', '%2$s', ''],
    ['{ Object[] parts = {"a", clean}; }', 'Object[] parts = {"a", input};', '%2$s', ''],
    ['', 'Object[] parts = {"a", clean};', '%2$s', 'mutate(parts, input);'],
    ['', 'Object[] parts = {"a", clean};', '%3$s', ''],
  ]) {
    assert.ok((await findings(t, `String clean = ${escape('input')};
      ${prefix} ${declaration}
      response.getWriter().printf(${JSON.stringify(format)}, parts);
      ${suffix}`)).length, prefix + declaration + format + suffix);
  }
});
