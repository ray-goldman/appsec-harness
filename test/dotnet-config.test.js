'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { scan } = require('../src/engine');
async function findings(t, text, file = 'Web.config') {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kayfabe-netcfg-'));
  t.after(() => {
    assert.equal(path.dirname(fs.realpathSync(root)), fs.realpathSync(os.tmpdir()));
    assert.ok(path.basename(root).startsWith('kayfabe-netcfg-'));
    fs.rmSync(root, { recursive: true, force: true });
  });
  fs.writeFileSync(path.join(root, file), text);
  return (await scan(root, { includeTests: true })).findings.filter(f => f.ruleId.startsWith('NETCFG-') || ['CS-TLS-002', 'CS-XSS-001'].includes(f.ruleId));
}
const web = child => `<configuration><system.web>${child}</system.web></configuration>`;
test('exact ASP.NET config settings are detected, including multiline and single quotes', async t => {
  for (const [child, rule] of [
    ["<compilation\n debug='true' />", 'NETCFG-DEBUG-001'],
    ['<trace enabled="true" localOnly="false" />', 'NETCFG-DEBUG-001'],
    ['<customErrors mode="Off" />', 'NETCFG-ERR-001'],
    ['<httpCookies httpOnlyCookies="false" />', 'NETCFG-COOKIE-001'],
    ['<httpCookies requireSSL="false" />', 'NETCFG-COOKIE-001'],
    ['<authentication mode="Forms"><forms requireSSL="false" /></authentication>', 'NETCFG-FORMS-001'],
    ['<sessionState cookieless="UseUri" />', 'NETCFG-FORMS-001'],
  ]) assert.ok((await findings(t, web(child))).some(f => f.ruleId === rule), rule);
  const result = await findings(t, '<configuration>\n<system.webServer>\n<httpErrors\n errorMode="Detailed" />\n</system.webServer></configuration>');
  assert.equal(result[0]?.ruleId, 'NETCFG-ERR-001');
  assert.equal(result[0]?.line, 3);
  assert.ok((await findings(t, '\uFEFF<?xml version="1.0" encoding="utf-8"?>' + web('<customErrors mode="Off" />'))).some(f => f.ruleId === 'NETCFG-ERR-001'));
});
test('WCF disables transport security only in supported binding context', async t => {
  const wrap = inner => `<configuration><system.serviceModel><bindings><basicHttpBinding><binding>${inner}</binding></basicHttpBinding></bindings></system.serviceModel></configuration>`;
  assert.ok((await findings(t, wrap('<security mode="None" />'))).some(f => f.ruleId === 'NETCFG-WCF-001'));
  assert.equal((await findings(t, wrap('<security mode="Transport"><transport clientCredentialType="None" /></security>'))).length, 0);
  const faults = '<configuration><system.serviceModel><behaviors><serviceBehaviors><behavior><serviceDebug includeExceptionDetailInFaults="true" /></behavior></serviceBehaviors></behaviors></system.serviceModel></configuration>';
  assert.ok((await findings(t, faults)).some(f => f.ruleId === 'NETCFG-ERR-001'));
});
test('safe values, local tracing, lookalikes and inactive XML are quiet', async t => {
  for (const child of [
    '<compilation debug="false" />', '<trace enabled="true" localOnly="true" />', '<trace enabled="true" />',
    '<customErrors mode="RemoteOnly" />', '<httpCookies httpOnlyCookies="true" requireSSL="true" />',
    '<authentication mode="Forms"><forms requireSSL="true" cookieless="UseCookies" /></authentication>',
    '<sessionState cookieless="UseCookies" />', '<compilation-backup debug="true" />',
    '<authentication mode="Windows"><forms requireSSL="false" cookieless="UseUri" /></authentication>',
    '<compilation data-debug="true" />', '<customErrors data-mode="Off" />',
    '<!-- <compilation debug="true" /> -->', '<![CDATA[<customErrors mode="Off" />]]>',
    '<add key="example" value="&lt;customErrors mode=&quot;Off&quot; /&gt;" />',
  ]) assert.equal((await findings(t, web(child))).length, 0, child);
  for (const text of ['<settings><customErrors mode="Off" /></settings>', '<configuration><appSettings><customErrors mode="Off" /></appSettings></configuration>']) {
    assert.equal((await findings(t, text)).length, 0);
  }
});
test('ambiguous, malformed, namespaced, transformed and oversized config is not interpreted', async t => {
  for (const text of [
    web('<customErrors mode="Off" mode="On" />'), web('<customErrors mode="Off" />').replace('</system.web>', '</bad>'),
    web('<customErrors mode="Off" />').replace('<configuration>', '<configuration xmlns="urn:custom">'),
    '<!DOCTYPE configuration [<!ENTITY x SYSTEM "file:///unused">]>' + web('<customErrors mode="Off" />'),
    web('<customErrors mode="Off" />') + '<extra/>',
    web('<customErrors mode="Off" />') + ' '.repeat(1024 * 1024),
    web('<customErrors mode="Off" xdt:Transform="Remove" />'),
    web('<!-- a -- b --><customErrors mode="Off" />'),
    web('&undefined;<customErrors mode="Off" />'),
    '<?xml garbage?>' + web('<customErrors mode="Off" />'),
    web('\u0001<customErrors mode="Off" />'),
    web(']]><customErrors mode="Off" />'),
    web('<customErrors mode="Off" / >'),
  ]) assert.equal((await findings(t, text)).length, 0);
  assert.equal((await findings(t, web('<customErrors mode="Off" />'), 'Web.Release.config')).length, 0);
});
test('obsolete TLS selection is distinct from safe defaults, removal and lookalike APIs', async t => {
  for (const op of ['=', '|=']) {
    const f = await findings(t, `using System.Net; class C { void M() { ServicePointManager.SecurityProtocol ${op} SecurityProtocolType.Tls | SecurityProtocolType.Tls12; } }`, 'Net.cs');
    assert.ok(f.some(x => x.ruleId === 'CS-TLS-002'));
  }
  for (const body of [
    'ServicePointManager.SecurityProtocol = SecurityProtocolType.SystemDefault;',
    'ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13;',
    'ServicePointManager.SecurityProtocol &= ~SecurityProtocolType.Tls;',
    '// ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;',
    'var example = "ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;";',
  ]) assert.equal((await findings(t, `using System.Net; class C { void M() {\n${body}\n} }`, 'Net.cs')).length, 0);
  assert.equal((await findings(t, 'using System.Net; class ServicePointManager {} class C { void M() { ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls; } }', 'Net.cs')).length, 0);
  assert.equal((await findings(t, 'using System.Net; class Options { public SecurityProtocolType SecurityProtocol; } class C { void M(Options ServicePointManager) { ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls; } }', 'Net.cs')).length, 0);
  assert.equal((await findings(t, 'using System.Net; class C { void M() { options.ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls; } }', 'Net.cs')).length, 0);
  assert.equal((await findings(t, 'using System.Net; class Options { public System.Net.SecurityProtocolType Tls; } class C { void M(Options SecurityProtocolType) { ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls; } }', 'Net.cs')).length, 0);
});
test('Razor encoding does not establish safety in unknown or dynamically produced contexts', async t => {
  const safe = '<div class="description">@Html.Raw(System.Net.WebUtility.HtmlEncode(Model.Description))</div>';
  // The existing standalone false positive remains until Razor context is modeled.
  assert.ok((await findings(t, safe, 'Details.cshtml')).some(f => f.ruleId === 'CS-XSS-001'));
  for (const text of [
    safe.replace('HtmlEncode(Model.Description)', 'HtmlEncode(Model.Description) + Model.Other'),
    safe.replace('System.Net.WebUtility.HtmlEncode', 'Custom.HtmlEncode'),
    '<script>@Html.Raw(System.Net.WebUtility.HtmlEncode(Model.Description))</script>',
    '<div>@Html.Raw(Model.Description)</div>',
    safe + '@Html.Raw(Model.Other)',
    '@functions { class System {} }\n' + safe,
    '<script>\n' + safe + '\n</script>',
    '<div>@Html.Raw(Model.Prefix)</div>\n' + safe,
  ]) assert.ok((await findings(t, text, 'Details.cshtml')).some(f => f.ruleId === 'CS-XSS-001'));
});
