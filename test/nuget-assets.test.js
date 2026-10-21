'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { parseManifest, isManifest, LOCKFILES } = require('../src/supply/manifests');

test('reads direct and transitive NuGet versions from packages.lock.json', () => {
  const parsed = parseManifest('src/packages.lock.json', JSON.stringify({ dependencies: { 'net8.0': {
    'Microsoft.Data.SqlClient': { type: 'Direct', requested: '[5.0.0, )', resolved: '5.2.0' },
    'System.Formats.Asn1': { type: 'Transitive', resolved: '8.0.1' },
  } } }));
  assert.deepEqual(parsed.deps.map(d => [d.name, d.version, d.direct]), [
    ['microsoft.data.sqlclient', '5.2.0', true], ['system.formats.asn1', '8.0.1', false],
  ]);
  assert.ok(LOCKFILES.nuget.includes('packages.lock.json'));
});

test('reads project.assets.json dependency versions and directness without executing project code', () => {
  const parsed = parseManifest('obj/project.assets.json', JSON.stringify({
    targets: { 'net8.0': { 'Example.Direct/1.0.0': {}, 'Example.Transitive/2.1.0': {} } },
    libraries: { 'Example.Direct/1.0.0': { type: 'package' }, 'Example.Transitive/2.1.0': { type: 'package' } },
    project: { frameworks: { 'net8.0': { dependencies: { 'Example.Direct': { target: 'Package' } } } } },
  }));
  assert.deepEqual(parsed.deps.map(d => [d.name, d.version, d.direct]), [
    ['example.direct', '1.0.0', true], ['example.transitive', '2.1.0', false],
  ]);
  assert.equal(isManifest('obj/project.assets.json'), true);
});

test('parses direct PackageReference values and preserves floating versions as specs', () => {
  const parsed = parseManifest('App.csproj', '<Project><ItemGroup><PackageReference Include="Example.One" Version="1.2.3"/><PackageReference Include="Example.Two"><Version>*</Version></PackageReference></ItemGroup></Project>');
  assert.deepEqual(parsed.deps.map(d => [d.name, d.version, d.spec, d.direct]), [
    ['example.one', '1.2.3', '1.2.3', true], ['example.two', null, '*', true],
  ]);
  assert.equal(parsed.manifestFor, 'nuget');
});
