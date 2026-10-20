'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { CODE_RULES } = require('../src/rules');
const rule = CODE_RULES.find((rule) => rule.id === 'PHP-CODE-001');
const hits = (code) => rule.checkCode({ code, raw: code, codeLines: code.split('\n') });
test('PHP code execution rule has a structured checker', () => {
  const rule = CODE_RULES.find((rule) => rule.id === 'PHP-CODE-001');
  assert.equal(typeof rule.checkCode, 'function');
});
test('unknown dynamic evaluation stays a review and constant code is quiet', () => {
  const findings = hits('eval($formula); eval("1 + 2;");');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].kind, 'review');
});
test('request aliases reach each code sink independently', () => {
  const findings = hits(`$formula = $_POST['formula'];
$alias = $formula;
eval($alias); eval($unknown); eval($_GET['formula']);`);
  assert.deepEqual(findings.map((f) => f.kind), ['vulnerability', 'review', 'vulnerability']);
});
test('comments and quoted examples are not executable calls', () => {
  assert.deepEqual(hits(`// eval($formula);
/* eval($formula); */
$example = 'eval($formula);';
eval('1 + 2;');`), []);
});
test('assignments are ordered and function scopes do not leak', () => {
  const findings = hits(`$formula = $_POST['formula'];
$formula = '1 + 2;';
eval($formula);
function first() { $local = $_GET['formula']; }
function second() { eval($local); }`);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].kind, 'review');
});
test('nested multiline calls preserve alias source', () => {
  const findings = hits(`$formula = $_POST['formula'];
eval(
 trim(
  $formula
 )
);`);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 2);
  assert.equal(findings[0].kind, 'vulnerability');
});
test('legacy PHP code execution APIs retain request source coverage', () => {
  const findings = hits(`assert($_POST['formula']);
create_function('', $_POST['formula']);
preg_replace('/.*/e', $_POST['formula'], $subject);
call_user_func($_POST['handler'], 'example');
$handler($_GET['formula']);`);
  assert.equal(findings.length, 5);
  assert.deepEqual(findings.map((f) => f.kind), ['vulnerability', 'vulnerability', 'vulnerability', 'vulnerability', 'review']);
});
test('request keys selecting a fixed dispatch map are not request-controlled code', () => {
  const findings = hits(`$formulas = ['sum' => '1 + 2;'];
eval($formulas[$_POST['formula']]);
eval($unknown[$_POST['formula']]);`);
  assert.ok(findings.every((f) => f.kind === 'review'));
});
test('heredoc and nowdoc examples do not become code execution calls', () => {
  assert.deepEqual(hits(`$example = <<<'TEXT'
eval($formula);
TEXT;
$another = <<<TEXT
eval($formula);
TEXT;
`), []);
});
test('calls in HTML outside PHP tags are not PHP execution', () => {
  assert.deepEqual(hits(`<p>eval($formula);</p>
<?php $value = '1 + 2;'; ?>
<p>eval($formula);</p>`), []);
});
test('conditional reassignment cannot erase a request path', () => {
  const findings = hits(`$formula = $_POST['formula'];
if ($condition) { $formula = '1 + 2;'; }
eval($formula);`);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].kind, 'vulnerability');
});
test('method calls named like stream readers do not establish a PHP input source', () => {
  const findings = hits(`eval($reader->file_get_contents($path));`);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].kind, 'review');
});
test('numeric conversions and request-dependent booleans are not injected PHP text', () => {
  assert.deepEqual(hits(`eval((int) $_POST['number']);
eval(intval($_POST['number']));
$matches = $_POST['formula'] === 'sum';
eval($matches);
eval($_POST['formula'] ? '1 + 2;' : '3 + 4;');`), []);
});
test('string interpolation and concatenation preserve actual request data', () => {
  const findings = hits(`$formula = $_POST['formula'];
eval("return $formula;");
eval('return ' . $formula . ';');`);
  assert.equal(findings.length, 2);
  assert.ok(findings.every((f) => f.kind === 'vulnerability'));
});
test('engine preserves review classification and every independent code sink', async () => {
  const { scan } = require('../src/engine');
  const path = require('node:path');
  const result = await scan(path.join(__dirname, '../corpus/php-code-precision/vuln'));
  const findings = result.findings.filter((f) => f.ruleId === rule.id);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].kind, 'vulnerability');
  assert.equal(findings[0].taint.source, '$_POST');
});
test('known callbacks receiving request arguments do not imply code injection', () => {
  const findings = hits(`$known = 'strtolower';
$known($_POST['value']);
$closure = function ($value) { return $value; };
$closure($_POST['value']);
$callback = $_POST['handler'];
$callback('value');
$unknown($_POST['value']);`);
  assert.deepEqual(findings.map((f) => f.kind), ['vulnerability', 'review']);
});
test('unbraced conditional writes preserve the other request path', () => {
  const findings = hits(`$formula = $_POST['formula']; if ($safe) $formula = '1 + 2;'; eval($formula);`);
  assert.ok(findings.some((f) => f.kind === 'vulnerability'));
});
test('loop-carried request assignments reach earlier sinks on a later iteration', () => {
  const findings = hits(`$formula = '1 + 2;'; while ($more) { eval($formula); $formula = $_POST['formula']; }`);
  assert.ok(findings.some((f) => f.kind === 'vulnerability'));
});
test('indexed request writes reach indexed code evaluation', () => {
  const findings = hits(`$formulas = ['1 + 2;']; $formulas['chosen'] = $_POST['formula']; eval($formulas['chosen']);`);
  assert.ok(findings.some((f) => f.kind === 'vulnerability'));
});
test('indexed writes remain specific and survive conditional joins', () => {
  const findings = hits(`$formulas = ['1 + 2;'];
$formulas['safe'] = '3 + 4;';
if ($condition) { $formulas['chosen'] = $_POST['formula']; }
eval($formulas['safe']);
eval($formulas['chosen']);`);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 5);
  assert.equal(findings[0].kind, 'vulnerability');
});
test('loop replay respects an unconditional constant overwrite before the next iteration', () => {
  assert.deepEqual(hits(`$formula = '1 + 2;';
while ($more) {
  eval($formula);
  $formula = $_POST['formula'];
  $formula = '3 + 4;';
}`), []);
});
test('shell command output is unknown executable data, not a PHP string literal', () => {
  const findings = hits('eval(`formula_provider`);');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].kind, 'review');
});
test('loop analysis reaches a fixed point across multiple alias transfers', () => {
  const findings = hits(`$a = '1 + 2;'; $b = '3 + 4;'; $c = '5 + 6;';
while ($more) { eval($a); $a = $b; $b = $c; $c = $_POST['formula']; }`);
  assert.ok(findings.some((f) => f.kind === 'vulnerability'));
});
test('loop analysis widens unresolved aliases when its replay budget is exhausted', () => {
  const raw = `$a = '1 + 2;'; $b = '3 + 4;'; $c = '5 + 6;';
while ($more) { eval($a); $a = $b; $b = $c; $c = $_POST['formula']; }`;
  const findings = rule.checkCode({ raw, maxReplayTokens: 0 });
  assert.ok(findings.some((f) => f.kind === 'review'));
});
test('loop widening still respects a constant overwrite before the sink', () => {
  const raw = `$a = '1 + 2;';
while ($more) { $a = '3 + 4;'; eval($a); $a = $_POST['formula']; }`;
  assert.deepEqual(rule.checkCode({ raw, maxReplayTokens: 0 }), []);
});
test('shadowed numeric conversion functions do not prove safe code', () => {
  const findings = hits(`namespace App;
function intval($value) { return $value; }
eval(intval($_POST['formula']));
eval(\\intval($_POST['formula']));`);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].kind, 'review');
});
test('namespaced calls require global qualification for builtin transformation proof', () => {
  const findings = hits(`namespace App;
eval(trim($_POST['formula']));
eval(\\trim($_POST['formula']));`);
  assert.deepEqual(findings.map((f) => f.kind), ['review', 'vulnerability']);
});
test('oversized constant proofs degrade to review instead of growing symbolic state without bound', () => {
  const findings = hits('eval("' + '1 + '.repeat(1500) + '2;");');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].kind, 'review');
});
test('loop fixedpoint analysis bounds exponentially growing constant expressions', () => {
  const findings = hits(`$formula = '1 + 2;';
while ($more) { $formula = $formula . $formula; eval($formula); }`);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].kind, 'review');
});
test('imported function aliases do not inherit builtin conversion proofs', () => {
  const findings = hits(`use function Vendor\\identity as intval;
eval(intval($_POST['formula']));
eval(\\intval($_POST['formula']));`);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].kind, 'review');
});
test('function imports do not create local variable scopes', () => {
  const findings = hits(`$formula = $_POST['formula'];
use function Vendor\\identity as custom;
eval($formula);`);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].kind, 'vulnerability');
});
