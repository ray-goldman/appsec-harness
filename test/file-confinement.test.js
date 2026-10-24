'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { callTool } = require('../src/mcp/server');
const { validateTriage, buildTriageRequest } = require('../src/triage');

function fixture(t) {
  const owned = fs.mkdtempSync(path.join(os.tmpdir(), 'kayfabe-confine-'));
  t.after(() => {
    assert.equal(path.dirname(fs.realpathSync(owned)), fs.realpathSync(os.tmpdir()));
    assert.ok(path.basename(owned).startsWith('kayfabe-confine-'));
    fs.rmSync(owned, { recursive: true, force: true });
  });
  const root = path.join(owned, 'target'), outside = path.join(owned, 'target-sibling'), report = path.join(owned, 'report');
  for (const dir of [path.join(root, 'src'), outside, report]) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(root, 'src/file.js'), 'INSIDE_MARKER\nsecond line\n');
  fs.writeFileSync(path.join(outside, 'file.js'), 'OUTSIDE_DUMMY_MARKER\n');
  const finding = { id: 'F0001', fingerprint: '1234567890abcdef', ruleId: 'JS-PATH-001', file: 'src/file.js', line: 1,
    status: 'open', severity: 'high', confidence: 'medium', owasp: 'A01', owaspName: 'Broken Access Control', cwe: [22], snippet: '', source: 'code' };
  const result = { target: { root, name: 'controlled-fixture' }, findings: [finding], surface: [] };
  const save = () => fs.writeFileSync(path.join(report, 'findings.json'), JSON.stringify(result));
  save();
  const triage = file => ({ schema: 'appsec-harness/triage@1', reviewer: 'regression', verdicts: [{ fingerprint: finding.fingerprint,
    verdict: 'false_positive', rationale: 'Controlled regression evidence must stay inside the selected root.', evidence: [{ file, line: 1 }] }] });
  const read = file => callTool('appsec_read_code', { report_dir: report, file, start: 1, end: 2 });
  const link = (destination, name) => fs.symlinkSync(destination, path.join(root, name), process.platform === 'win32' ? 'junction' : 'dir');
  return { owned, root, outside, report, finding, result, save, triage, read, link };
}

test('MCP source reads and all ordinary evidence remain usable', async t => {
  const f = fixture(t);
  assert.match((await f.read('src/file.js')).code, /INSIDE_MARKER/);
  assert.equal(validateTriage(f.result, f.triage('src/file.js')).ok, true);
  const triage = f.triage('src/file.js');
  triage.additionalFindings = [{ title: 'Controlled extra', severity: 'low', owasp: 'A01', cwe: [22], file: 'src/file.js', line: 2,
    rationale: 'A normal source location remains valid evidence.', evidence: [{ file: 'src/file.js', line: 1 }] }];
  assert.equal(validateTriage(f.result, triage).ok, true);
  assert.match(buildTriageRequest(f.result).items[0].context.code, /INSIDE_MARKER/);
});

test('MCP reads and triage reject an outside directory junction', async t => {
  const f = fixture(t); f.link(f.outside, 'linked');
  await assert.rejects(f.read('linked/file.js'));
  assert.equal(validateTriage(f.result, f.triage('linked/file.js')).ok, false);
});

test('nested ancestor links and links to in-root directories are rejected', async t => {
  const f = fixture(t); fs.mkdirSync(path.join(f.root, 'nested'));
  f.link(f.outside, 'nested/escape'); f.link(path.join(f.root, 'src'), 'alias');
  for (const name of ['nested/escape/file.js', 'alias/file.js']) {
    await assert.rejects(f.read(name));
    assert.equal(validateTriage(f.result, f.triage(name)).ok, false);
  }
});

test('leaf symlinks cannot supply code or evidence', async t => {
  const f = fixture(t);
  try { fs.symlinkSync(path.join(f.outside, 'file.js'), path.join(f.root, 'leaf.js'), 'file'); }
  catch (error) { if (process.platform === 'win32' && error.code === 'EPERM') return t.skip('File symlinks require privilege; directory junction tests are mandatory.'); throw error; }
  await assert.rejects(f.read('leaf.js'));
  assert.equal(validateTriage(f.result, f.triage('leaf.js')).ok, false);
});

test('path prefixes, absolute paths and invalid arguments cannot escape the relative-file contract', async t => {
  const f = fixture(t);
  for (const name of ['../target-sibling/file.js', path.join(f.outside, 'file.js'), path.join(f.root, 'src/file.js'), '', null, 'src\0/file.js']) {
    await assert.rejects(f.read(name));
    assert.equal(validateTriage(f.result, f.triage(name)).ok, false);
  }
  if (process.platform === 'win32') for (const name of ['C:src/file.js', 'src/file.js:stream', '\\\\?\\C:\\outside.txt']) {
    await assert.rejects(f.read(name));
    assert.equal(validateTriage(f.result, f.triage(name)).ok, false);
  }
});

test('directory and nonexistent evidence are rejected without reading them', async t => {
  const f = fixture(t);
  for (const name of ['src', 'missing.js']) {
    await assert.rejects(f.read(name));
    assert.equal(validateTriage(f.result, f.triage(name)).ok, false);
  }
});

test('a deliberately selected root alias is anchored to its canonical directory', async t => {
  const f = fixture(t), alias = path.join(f.owned, 'selected-root');
  fs.symlinkSync(f.root, alias, process.platform === 'win32' ? 'junction' : 'dir');
  f.result.target.root = alias + path.sep; f.save();
  assert.match((await f.read('src/file.js')).code, /INSIDE_MARKER/);
  assert.equal(validateTriage(f.result, f.triage('src/file.js')).ok, true);
});

test('every evidence channel rejects linked parents', t => {
  const f = fixture(t); f.link(f.outside, 'linked');
  for (const verdict of ['false_positive', 'accepted_risk', 'true_positive', 'needs_review']) {
    const triage = f.triage('linked/file.js'); triage.verdicts[0].verdict = verdict;
    assert.equal(validateTriage(f.result, triage).ok, false, verdict);
  }
  for (const field of ['file', 'evidence']) {
    const triage = f.triage('src/file.js');
    triage.additionalFindings = [{ title: 'Controlled extra', severity: 'low', owasp: 'A01', cwe: [22],
      file: field === 'file' ? 'linked/file.js' : 'src/file.js', line: 1,
      rationale: 'Linked source evidence must never cross the selected root.',
      evidence: [{ file: field === 'evidence' ? 'linked/file.js' : 'src/file.js', line: 1 }] }];
    assert.equal(validateTriage(f.result, triage).ok, false, field);
  }
});

test('triage and MCP finding previews omit context beneath linked directories', async t => {
  const f = fixture(t); f.link(f.outside, 'linked'); f.finding.file = 'linked/file.js'; f.save();
  assert.equal(buildTriageRequest(f.result).items[0].context, null);
  const response = await callTool('appsec_findings', { report_dir: f.report });
  assert.equal(response.items[0].context, null);
  assert.ok(!JSON.stringify(response).includes('OUTSIDE_DUMMY_MARKER'));
});

test('MCP search retains normal matches and skips directory junctions', async t => {
  const f = fixture(t); f.link(f.outside, 'linked');
  const inside = await callTool('appsec_search_code', { report_dir: f.report, pattern: 'INSIDE_MARKER' });
  assert.equal(inside.matches, 1);
  const outside = await callTool('appsec_search_code', { report_dir: f.report, pattern: 'OUTSIDE_DUMMY_MARKER' });
  assert.equal(outside.matches, 0);
});

test('file limits reject oversized reads, evidence and previews while accepting the exact bound', async t => {
  const f = fixture(t), { readConfinedText, MAX_SOURCE_BYTES } = require('../src/confined-read');
  fs.writeFileSync(path.join(f.root, 'large.js'), Buffer.alloc(MAX_SOURCE_BYTES + 1, 65));
  await assert.rejects(f.read('large.js'));
  assert.equal(validateTriage(f.result, f.triage('large.js')).ok, false);
  f.finding.file = 'large.js';
  assert.equal(buildTriageRequest(f.result).items[0].context, null);
  fs.truncateSync(path.join(f.root, 'large.js'), MAX_SOURCE_BYTES);
  assert.equal(readConfinedText(f.root, 'large.js').length, MAX_SOURCE_BYTES);
});

test('empty files and the path-depth boundary have explicit behavior', t => {
  const f = fixture(t), { readConfinedText } = require('../src/confined-read');
  fs.writeFileSync(path.join(f.root, 'empty.js'), '');
  assert.equal(readConfinedText(f.root, 'empty.js'), '');
  const allowed = Array(39).fill('d').concat('file.js').join('/');
  fs.mkdirSync(path.dirname(path.join(f.root, allowed)), { recursive: true });
  fs.writeFileSync(path.join(f.root, allowed), 'depth-boundary');
  assert.equal(readConfinedText(f.root, allowed), 'depth-boundary');
  const denied = Array(40).fill('d').concat('file.js').join('/');
  fs.mkdirSync(path.dirname(path.join(f.root, denied)), { recursive: true });
  fs.writeFileSync(path.join(f.root, denied), 'too-deep');
  assert.throws(() => readConfinedText(f.root, denied));
  assert.equal(validateTriage(f.result, f.triage(denied)).ok, false);
});

test('descriptors close after a successful read and an injected read failure', t => {
  const f = fixture(t), { readConfinedText } = require('../src/confined-read');
  const originalOpen = fs.openSync, originalRead = fs.readSync;
  let descriptor;
  const open = t.mock.method(fs, 'openSync', (...args) => { descriptor = originalOpen(...args); return descriptor; });
  try {
    assert.match(readConfinedText(f.root, 'src/file.js'), /INSIDE_MARKER/);
    assert.throws(() => fs.fstatSync(descriptor), { code: 'EBADF' });
    const read = t.mock.method(fs, 'readSync', () => { throw new Error('injected failure'); });
    try {
      assert.throws(() => readConfinedText(f.root, 'src/file.js'), /injected failure/);
      assert.throws(() => fs.fstatSync(descriptor), { code: 'EBADF' });
    } finally { read.mock.restore(); }
  } finally { open.mock.restore(); }
  assert.equal(fs.readSync, originalRead);
});

test('swapping a parent before open cannot expose the outside descriptor', t => {
  const f = fixture(t), { readConfinedText } = require('../src/confined-read');
  const originalOpen = fs.openSync, originalRead = fs.readSync;
  let changed = false, readCalls = 0, descriptor;
  const open = t.mock.method(fs, 'openSync', (file, ...args) => {
    if (!changed && file === path.join(f.root, 'src/file.js')) {
      changed = true; fs.renameSync(path.join(f.root, 'src'), path.join(f.root, 'parked')); f.link(f.outside, 'src');
    }
    descriptor = originalOpen(file, ...args); return descriptor;
  });
  const read = t.mock.method(fs, 'readSync', (...args) => { readCalls++; return originalRead(...args); });
  try {
    assert.throws(() => readConfinedText(f.root, 'src/file.js'));
    assert.equal(changed, true); assert.equal(readCalls, 0);
    assert.throws(() => fs.fstatSync(descriptor), { code: 'EBADF' });
  } finally { read.mock.restore(); open.mock.restore(); }
});

test('swapping a parent after open is detected before reading and closes the handle', t => {
  const f = fixture(t), { readConfinedText } = require('../src/confined-read');
  const originalStat = fs.fstatSync, originalRead = fs.readSync;
  let descriptor, readCalls = 0, changed = false, mutationError;
  const stat = t.mock.method(fs, 'fstatSync', (fd, ...args) => {
    const result = originalStat(fd, ...args);
    if (!changed) {
      descriptor = fd; changed = true;
      try { fs.renameSync(path.join(f.root, 'src'), path.join(f.root, 'parked')); f.link(f.outside, 'src'); }
      catch (error) { mutationError = error; throw error; }
    }
    return result;
  });
  const read = t.mock.method(fs, 'readSync', (...args) => { readCalls++; return originalRead(...args); });
  try {
    assert.throws(() => readConfinedText(f.root, 'src/file.js'));
    assert.equal(changed, true);
    assert.equal(readCalls, 0);
    assert.throws(() => originalStat(descriptor), { code: 'EBADF' });
    if (process.platform === 'win32' && mutationError?.code === 'EPERM') t.skip('Windows blocks renaming the directory while its file is open; POSIX exercises this race.');
    else assert.equal(mutationError, undefined);
  } finally { read.mock.restore(); stat.mock.restore(); }
});

test('an observed path change during the read is not approved as evidence', t => {
  const f = fixture(t), { readConfinedText } = require('../src/confined-read');
  const originalRead = fs.readSync; let changed = false, mutationError;
  const read = t.mock.method(fs, 'readSync', (...args) => {
    const count = originalRead(...args);
    if (!changed) {
      changed = true;
      try { fs.renameSync(path.join(f.root, 'src'), path.join(f.root, 'parked')); f.link(f.outside, 'src'); }
      catch (error) { mutationError = error; throw error; }
    }
    return count;
  });
  try {
    assert.throws(() => readConfinedText(f.root, 'src/file.js')); assert.equal(changed, true);
    if (process.platform === 'win32' && mutationError?.code === 'EPERM') t.skip('Windows blocks renaming the directory while its file is open; POSIX exercises this race.');
    else assert.equal(mutationError, undefined);
  }
  finally { read.mock.restore(); }
});

test('file growth during reading is rejected', t => {
  const f = fixture(t), { readConfinedText } = require('../src/confined-read');
  const originalRead = fs.readSync; let changed = false;
  const read = t.mock.method(fs, 'readSync', (...args) => {
    if (!changed) { fs.appendFileSync(path.join(f.root, 'src/file.js'), 'extra'); changed = true; }
    return originalRead(...args);
  });
  try { assert.throws(() => readConfinedText(f.root, 'src/file.js')); assert.equal(changed, true); }
  finally { read.mock.restore(); }
});

test('duplicate evidence does not reuse a stale pathname approval', t => {
  const f = fixture(t), originalClose = fs.closeSync; let changed = false;
  const close = t.mock.method(fs, 'closeSync', fd => {
    originalClose(fd);
    if (!changed) { fs.renameSync(path.join(f.root, 'src'), path.join(f.root, 'parked')); f.link(f.outside, 'src'); changed = true; }
  });
  const triage = f.triage('src/file.js'); triage.verdicts[0].evidence.push({ file: 'src/file.js', line: 2 });
  try { assert.equal(validateTriage(f.result, triage).ok, false); assert.equal(changed, true); }
  finally { close.mock.restore(); }
});

test('MCP search revalidates a file when the tree changes after walking', async t => {
  const f = fixture(t), originalStat = fs.lstatSync; let changed = false;
  const stat = t.mock.method(fs, 'lstatSync', (file, ...args) => {
    const result = originalStat(file, ...args);
    if (!changed && file === path.join(f.root, 'src/file.js')) {
      fs.renameSync(path.join(f.root, 'src'), path.join(f.root, 'parked')); f.link(f.outside, 'src'); changed = true;
    }
    return result;
  });
  try {
    const result = await callTool('appsec_search_code', { report_dir: f.report, pattern: 'OUTSIDE_DUMMY_MARKER' });
    assert.equal(changed, true); assert.equal(result.matches, 0);
  } finally { stat.mock.restore(); }
});
