'use strict';
// The installer and GitHub endpoint are mocked: these tests never install or fetch.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const os = require('node:os');
const cp = require('node:child_process');

function updater(options = {}) {
  const calls = { spawn: [], removed: [], fetch: [], writes: [] };
  const temporaryRoot = path.resolve(__dirname, 'mock-temp');
  const fakeFs = {
    readFileSync() { throw new Error('no cached check'); },
    mkdirSync() {},
    writeFileSync(file, raw, settings) { calls.writes.push({ file, raw, settings }); if (options.cacheReadOnly) throw new Error('read only'); },
    renameSync() {},
    rmSync(file, settings) { calls.removed.push({ file, settings }); },
    mkdtempSync(prefix) { if (options.tempError) throw new Error('no temporary directory'); return prefix + 'fixture'; },
    statSync() { return { isFile: () => true }; },
  };
  const fakeProcess = {
    platform: options.platform || 'win32', execPath: path.join(temporaryRoot, 'node.exe'), pid: 123,
    stdin: {}, stderr: { fd: 2 },
    env: { PATH: 'trusted-path', npm_config_prefix: 'user-global-prefix',
      GIT_DIR: 'hostile-git', GIT_WORK_TREE: 'hostile-tree', GIT_CONFIG_COUNT: '1',
      GIT_CONFIG_KEY_0: 'url.ext::untrusted.insteadOf', GIT_CONFIG_VALUE_0: 'https://github.com/',
      GIT_CONFIG_PARAMETERS: 'hostile-config', git_config_global: 'case-insensitive-hostile',
      SSH_ASKPASS: 'hostile-askpass' },
  };
  const fakeRequire = id => {
    if (id === 'fs') return fakeFs;
    if (id === 'os') return { homedir: () => path.join(temporaryRoot, 'home'), tmpdir: () => temporaryRoot, devNull: options.platform === 'linux' ? '/dev/null' : '\\\\.\\NUL' };
    if (id === 'child_process') return { spawnSync(...args) { calls.spawn.push(args); return options.spawnResult || { status: 0 }; } };
    if (id === 'readline/promises') return { createInterface: () => ({ question: async () => options.answer || 'no', close() {} }) };
    if (id === '../package.json') return { version: '1.0.0' };
    return require(id);
  };
  const release = options.release || { tag_name: 'v1.1.0', html_url: 'https://github.com/ray-goldman/kayfabe/releases/tag/v1.1.0', name: 'Release' };
  const module = { exports: {} };
  const source = fs.readFileSync(path.join(__dirname, '../src/update.js'), 'utf8');
  vm.runInNewContext('(function(require,module,exports){' + source + '\n})', {
    process: fakeProcess, URL, AbortSignal, fetch: async (...args) => {
      calls.fetch.push(args);
      return { status: options.status || 200, ok: !options.status || options.status === 200, json: async () => release };
    },
  })(fakeRequire, module, module.exports);
  return { ...module.exports, calls, temporaryRoot, fakeProcess };
}
const stable = { version: '1.1.0', tag: 'v1.1.0' };

test('release installation isolates cwd and inherited Git settings while preserving npm prefix', () => {
  const api = updater();
  assert.equal(api.installRelease(stable).ok, true);
  const [command, args, opts] = api.calls.spawn[0];
  assert.equal(command, api.fakeProcess.execPath);
  assert.ok(args.includes('--ignore-scripts'));
  assert.equal(args.at(-1), 'git+https://github.com/ray-goldman/kayfabe.git#v1.1.0');
  assert.equal(path.dirname(opts.cwd), api.temporaryRoot);
  assert.ok(path.basename(opts.cwd).startsWith('kayfabe-update-'));
  assert.equal(opts.env.PATH, 'trusted-path');
  assert.equal(opts.env.npm_config_prefix, 'user-global-prefix');
  for (const name of ['GIT_DIR', 'GIT_WORK_TREE', 'GIT_CONFIG_PARAMETERS', 'git_config_global', 'SSH_ASKPASS']) assert.equal(opts.env[name], undefined, name);
  assert.equal(opts.env.GIT_ALLOW_PROTOCOL, 'https');
  assert.equal(opts.env.GIT_CONFIG_NOSYSTEM, '1');
  assert.notEqual(opts.env.GIT_CONFIG_GLOBAL, 'case-insensitive-hostile');
  assert.equal(opts.env.GIT_TERMINAL_PROMPT, '0');
  assert.equal(opts.env.GIT_CEILING_DIRECTORIES, path.dirname(opts.cwd));
  const settings = {};
  for (let i = 0; i < Number(opts.env.GIT_CONFIG_COUNT); i++) settings[opts.env['GIT_CONFIG_KEY_' + i]] = opts.env['GIT_CONFIG_VALUE_' + i];
  assert.equal(settings['core.fsmonitor'], 'false');
  assert.equal(settings['submodule.recurse'], 'false');
  assert.equal(settings['credential.helper'], '');
  assert.equal(path.dirname(settings['core.hooksPath']), opts.cwd);
  assert.equal(api.calls.removed.at(-1).file, opts.cwd);
});

test('installer cleanup and failure reporting cover nonzero and unavailable npm', () => {
  for (const spawnResult of [{ status: 1 }, { status: null, error: new Error('unavailable') }]) {
    const api = updater({ spawnResult });
    assert.equal(api.installRelease(stable).ok, false);
    assert.equal(api.calls.removed.at(-1).file, api.calls.spawn[0][2].cwd);
  }
});

test('Git configuration uses a private empty file compatible with Git for Windows', () => {
  const api = updater();
  assert.equal(api.installRelease(stable).ok, true);
  const opts = api.calls.spawn[0][2];
  assert.equal(path.dirname(opts.env.GIT_CONFIG_GLOBAL), opts.cwd);
  assert.equal(opts.env.GIT_CONFIG_SYSTEM, opts.env.GIT_CONFIG_GLOBAL);
  const written = api.calls.writes.find(w => w.file === opts.env.GIT_CONFIG_GLOBAL);
  assert.equal(written.raw, '');
  assert.equal(written.settings.flag, 'wx');
});

test('an unavailable isolation directory refuses installation', () => {
  const api = updater({ tempError: true });
  assert.equal(api.installRelease(stable).ok, false);
  assert.equal(api.calls.spawn.length, 0);
});

test('invalid or mismatched release tags never reach npm', () => {
  const api = updater();
  for (const tag of ['v1.1.0;echo unsafe', '--help', 'v1.1.0-beta', 'v2.0.0']) assert.equal(api.installRelease({ ...stable, tag }).ok, false);
  assert.equal(api.calls.spawn.length, 0);
});

test('automatic cache failure avoids networking while explicit checks remain possible', async () => {
  const api = updater({ cacheReadOnly: true });
  assert.equal((await api.checkForUpdate()).reason, 'cache-unavailable');
  assert.equal(api.calls.fetch.length, 0);
  assert.equal((await api.checkForUpdate({ force: true })).status, 'available');
  assert.equal(api.calls.spawn.length, 0);
  assert.equal(api.calls.fetch[0][1].redirect, 'error');
});

test('release discovery rejects foreign URLs and prereleases and handles no release', async () => {
  for (const release of [
    { tag_name: 'v1.1.0', html_url: 'https://evil.invalid/releases/tag/v1.1.0' },
    { tag_name: 'v1.1.0-beta', html_url: 'https://github.com/ray-goldman/kayfabe/releases/tag/v1.1.0-beta' },
  ]) assert.equal((await updater({ release }).checkForUpdate({ force: true })).reason, 'invalid-release');
  assert.equal((await updater({ status: 404 }).checkForUpdate({ force: true })).reason, 'no-release');
});

test('declining the prompt never starts npm; affirmative Linux install remains isolated', async () => {
  const no = updater();
  assert.equal((await no.promptForUpdate(stable)).accepted, false);
  assert.equal(no.calls.spawn.length, 0);
  const yes = updater({ answer: 'yes', platform: 'linux' });
  assert.equal((await yes.promptForUpdate(stable)).ok, true);
  assert.equal(yes.calls.spawn[0][0], 'npm');
  assert.equal(path.dirname(yes.calls.spawn[0][2].cwd), yes.temporaryRoot);
});

test('real Git URL expansion ignores a hostile ancestor and inherited Git directory', t => {
  if (cp.spawnSync('git', ['--version']).status !== 0) return t.skip('Git unavailable');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kayfabe-update-git-'));
  t.after(() => {
    assert.equal(path.dirname(fs.realpathSync(root)), fs.realpathSync(os.tmpdir()));
    assert.ok(path.basename(root).startsWith('kayfabe-update-git-'));
    fs.rmSync(root, { recursive: true, force: true });
  });
  for (const dir of ['.git/objects', '.git/refs/heads', 'scratch']) fs.mkdirSync(path.join(root, dir), { recursive: true });
  fs.writeFileSync(path.join(root, '.git/HEAD'), 'ref: refs/heads/main\n');
  fs.writeFileSync(path.join(root, '.git/config'), '[core]\n repositoryformatversion = 0\n bare = false\n[url "https://invalid.example/"]\n insteadOf = https://github.com/ray-goldman/\n');
  const canonical = 'https://github.com/ray-goldman/kayfabe.git';
  // --get-url expands configuration only: no remote or helper is contacted.
  assert.equal(cp.execFileSync('git', ['ls-remote', '--get-url', canonical], { cwd: root, encoding: 'utf8' }).trim(), 'https://invalid.example/kayfabe.git');
  let expanded, installerCalled = false;
  const fakeRequire = id => {
    if (id === 'os') return { ...os, tmpdir: () => path.join(root, 'scratch') };
    if (id === 'child_process') return { spawnSync(command, args, opts) {
      installerCalled = true;
      assert.ok(args.includes('--ignore-scripts'));
      expanded = cp.execFileSync('git', ['ls-remote', '--get-url', canonical], { cwd: opts.cwd, env: opts.env, encoding: 'utf8' }).trim();
      return { status: 0 };
    } };
    if (id === '../package.json') return { version: '1.0.0' };
    return require(id);
  };
  const module = { exports: {} };
  const source = fs.readFileSync(path.join(__dirname, '../src/update.js'), 'utf8');
  vm.runInNewContext('(function(require,module,exports){' + source + '\n})', {
    process: { platform: process.platform, execPath: process.execPath, pid: process.pid,
      stdin: process.stdin, stderr: process.stderr, env: { ...process.env, GIT_DIR: path.join(root, '.git') } },
    URL, AbortSignal,
  })(fakeRequire, module, module.exports);
  assert.equal(module.exports.installRelease(stable).ok, true);
  assert.equal(installerCalled, true);
  assert.equal(expanded, canonical);
  assert.equal(fs.readdirSync(path.join(root, 'scratch')).length, 0);
});
