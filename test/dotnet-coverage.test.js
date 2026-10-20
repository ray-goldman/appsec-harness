'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { scan } = require('../src/engine');
async function rules(t, code) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kayfabe-dotnet-'));
  t.after(() => {
    assert.equal(path.dirname(fs.realpathSync(root)), fs.realpathSync(os.tmpdir()));
    assert.ok(path.basename(root).startsWith('kayfabe-dotnet-'));
    fs.rmSync(root, { recursive: true, force: true });
  });
  fs.writeFileSync(path.join(root, 'Example.cs'), code);
  return (await scan(root, { includeTests: true })).findings.map(f => f.ruleId);
}
const controller = body => `using Microsoft.AspNetCore.Mvc;
using System.IO;
using System.Diagnostics;
public class PhotosController : ControllerBase {
${body}
}`;
const method = body => `public IActionResult Read([FromQuery] string input) { ${body} }`;
test('direct request filename reaches PhysicalFile without a containment proof', async t => {
  assert.ok((await rules(t, controller(method('return PhysicalFile(Path.Combine("/srv/photos", input), "image/jpeg");')))).includes('CS-PATH-001'));
});
test('path guards, basename transforms and unrelated parameter names do not trigger the direct-path rule', async t => {
  for (const body of [
    'return PhysicalFile(Path.Combine("/srv/photos", "default.jpg"), "image/jpeg");',
    'return PhysicalFile(Path.Combine("/srv/photos", Path.GetFileName(input)), "image/jpeg");',
    'var full = Path.GetFullPath(Path.Combine("/srv/photos", input)); if (!full.StartsWith("/srv/photos/")) return BadRequest(); return PhysicalFile(full, "image/jpeg");',
    'input = "default.jpg"; return PhysicalFile(Path.Combine("/srv/photos", input), "image/jpeg");',
  ]) assert.ok(!(await rules(t, controller(method(body)))).includes('CS-PATH-001'), body);
  assert.ok(!(await rules(t, controller(method('return Ok(input);') + '\npublic IActionResult Safe(string input) { return PhysicalFile(Path.Combine("/srv/photos", input), "image/jpeg"); }'))).includes('CS-PATH-001'));
});
test('direct request redirect is detected without flagging local redirect or guarded code', async t => {
  assert.ok((await rules(t, controller(method('return Redirect(input);')))).includes('CS-REDIRECT-001'));
  for (const body of ['return LocalRedirect(input);', 'return Redirect("/home");', 'return Redirect(Url.IsLocalUrl(input) ? input : "/");', 'if (!Url.IsLocalUrl(input)) return BadRequest(); return Redirect(input);']) {
    assert.ok(!(await rules(t, controller(method(body)))).includes('CS-REDIRECT-001'), body);
  }
});
test('shell concatenation with escaped quotes is detected and fixed argument lists stay quiet', async t => {
  assert.ok((await rules(t, controller(method(String.raw`Process.Start("/bin/sh", "-c \"nslookup " + input + "\""); return Ok();`)))).includes('CS-CMDI-002'));
  for (const code of [String.raw`Process.Start("/bin/sh", "-c \"echo constant\"");`, String.raw`Process.Start("/bin/sh", "-c \"echo " + "hello\"");`, 'var p = new ProcessStartInfo("nslookup"); p.ArgumentList.Add(input); Process.Start(p);']) {
    const found = await rules(t, controller(method(code + ' return Ok();')));
    assert.ok(!found.includes('CS-CMDI-001'));
    assert.ok(!found.includes('CS-CMDI-002'));
  }
});
test('MD5 on a password parameter is detected while PBKDF2 and ordinary checksums stay quiet', async t => {
  const hash = expr => `using System.Security.Cryptography; using System.Text;
class C { public static string Hash(string pw) { return System.BitConverter.ToString(${expr}); } }`;
  assert.ok((await rules(t, hash('MD5.Create().ComputeHash(Encoding.UTF8.GetBytes(pw))'))).includes('CS-CRYPTO-001'));
  assert.ok(!(await rules(t, hash('Rfc2898DeriveBytes.Pbkdf2(pw, salt, 600000, HashAlgorithmName.SHA256, 32)'))).includes('CS-CRYPTO-001'));
  assert.ok(!(await rules(t, hash('MD5.Create().ComputeHash(Encoding.UTF8.GetBytes(pw))').replaceAll('pw', 'fileContents'))).includes('CS-CRYPTO-001'));
});
test('explicit unsigned-token options are detected without treating signing-key validation as signature validation', async t => {
  const config = props => `using Microsoft.IdentityModel.Tokens;
class Startup { void Configure() { options.TokenValidationParameters = new TokenValidationParameters { ${props} }; } }`;
  assert.ok((await rules(t, config('ValidateIssuer = false, ValidateAudience = false, ValidateLifetime = false, RequireSignedTokens = false'))).includes('CS-JWT-001'));
  for (const props of ['RequireSignedTokens = true', 'ValidateIssuerSigningKey = false', 'ValidateIssuer = false', 'RequireSignedTokens = false, SignatureValidator = ValidateUsingExternalService']) {
    assert.ok(!(await rules(t, config(props))).includes('CS-JWT-001'), props);
  }
});
test('comments and string payloads cannot manufacture new C# findings', async t => {
  const payload = controller(method('return Redirect(input);'));
  for (const code of ['/* ' + payload + ' */', 'class C { string text = @"' + payload.replaceAll('"', '""') + '"; }', 'class C { string text = """' + payload + '"""; }']) {
    const found = await rules(t, code);
    assert.ok(!found.includes('CS-REDIRECT-001'));
    assert.ok(!found.includes('CS-PATH-001'));
  }
});
test('controller ownership and NonAction prevent treating ordinary helper parameters as request sources', async t => {
  for (const code of [
    'using Microsoft.AspNetCore.Mvc; public class HomeController : ControllerBase {} public class TextFormatter { private string Redirect(string value) => value; public string Format([FromQuery] string input) { return Redirect(input); } }',
    controller('public IActionResult Index() { return Helper("/home"); } [NonAction] public IActionResult Helper([FromQuery] string input) { return Redirect(input); }'),
    controller('public class Nested { private string Redirect(string value) => value; public string Format([FromQuery] string input) { return Redirect(input); } }'),
    controller('public static IActionResult Helper([FromQuery] string input) { return Redirect(input); }'),
  ]) assert.ok(!(await rules(t, code)).includes('CS-REDIRECT-001'));
});
test('later same-options JWT writes are outside the initializer-only rule', async t => {
  const code = 'using Microsoft.IdentityModel.Tokens; class Auth { void Configure(JwtBearerOptions options) { options.TokenValidationParameters = new TokenValidationParameters { RequireSignedTokens = false }; options.TokenValidationParameters.RequireSignedTokens = true; } }';
  assert.ok(!(await rules(t, code)).includes('CS-JWT-001'));
});
test('shell positional arguments and custom Process types are not shell command injection', async t => {
  for (const body of [
    String.raw`Process.Start("/bin/sh", "-c \"echo fixed\" -- " + input); return Ok();`,
    String.raw`Process.Start("/bin/sh", "script.sh " + input); return Ok();`,
  ]) assert.ok(!(await rules(t, controller(method(body)))).includes('CS-CMDI-002'));
  const shadow = controller(method(String.raw`Process.Start("/bin/sh", "-c \"nslookup " + input + "\""); return Ok();`)) + '\nclass Process { public static void Start(string executable, string arguments) {} }';
  assert.ok(!(await rules(t, shadow)).includes('CS-CMDI-002'));
});
