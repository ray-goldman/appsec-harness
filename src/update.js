'use strict';

const fs = require('fs');
const crypto = require('crypto');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { createInterface } = require('readline/promises');
const pkg = require('../package.json');

const RELEASE_API = 'https://api.github.com/repos/ray-goldman/kayfabe/releases/latest';
const INSTALL_REPO = 'git+https://github.com/ray-goldman/kayfabe.git';
const CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000;
const REQUEST_TIMEOUT_MS = 2000;

function parseVersion(input) {
  if (typeof input !== 'string') return null;
  const match = /^(?:v)?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/.exec(input);
  if (!match) return null;
  const prerelease = match[4] ? match[4].split('.') : [];
  if (prerelease.some((part) => /^0\d+$/.test(part))) return null;
  return { major: BigInt(match[1]), minor: BigInt(match[2]), patch: BigInt(match[3]), prerelease };
}

function compareVersions(left, right) {
  for (const key of ['major', 'minor', 'patch']) {
    if (left[key] > right[key]) return 1;
    if (left[key] < right[key]) return -1;
  }
  if (!left.prerelease.length && !right.prerelease.length) return 0;
  if (!left.prerelease.length) return 1;
  if (!right.prerelease.length) return -1;
  const count = Math.max(left.prerelease.length, right.prerelease.length);
  for (let i = 0; i < count; i++) {
    if (left.prerelease[i] === undefined) return -1;
    if (right.prerelease[i] === undefined) return 1;
    const a = left.prerelease[i], b = right.prerelease[i];
    if (a === b) continue;
    const aNumeric = /^\d+$/.test(a), bNumeric = /^\d+$/.test(b);
    if (aNumeric && bNumeric) return BigInt(a) > BigInt(b) ? 1 : -1;
    if (aNumeric !== bNumeric) return aNumeric ? -1 : 1;
    return a > b ? 1 : -1;
  }
  return 0;
}

function cachePaths() {
  const userKey = crypto.createHash('sha256').update(path.resolve(os.homedir())).digest('hex').slice(0, 16);
  return [
    path.join(os.homedir(), '.kayfabe', 'update-check.json'),
    path.join(os.tmpdir(), `kayfabe-update-check-${userKey}.json`),
  ];
}

function readCheckTime() {
  let latest = 0;
  for (const file of cachePaths()) {
    try {
      const data = JSON.parse(fs.readFileSync(file, 'utf8'));
      if (Number.isFinite(data.checkedAt) && data.checkedAt <= Date.now()) latest = Math.max(latest, data.checkedAt);
    } catch { /* try the fallback cache */ }
  }
  return latest;
}

function recordCheckTime(checkedAt) {
  for (const file of cachePaths()) {
    const dir = path.dirname(file);
    const temporary = `${file}.${process.pid}.tmp`;
    try {
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(temporary, JSON.stringify({ checkedAt }), { mode: 0o600 });
      fs.renameSync(temporary, file);
      return true;
    } catch {
      try { fs.rmSync(temporary, { force: true }); } catch { /* best effort */ }
    }
  }
  return false;
}

function unavailable(reason) {
  return { status: 'unavailable', currentVersion: pkg.version, release: null, reason };
}

function validRelease(data) {
  if (!data || data.draft || data.prerelease || typeof data.tag_name !== 'string') return null;
  const parsed = parseVersion(data.tag_name);
  if (!parsed || parsed.prerelease.length) return null;
  let url;
  try { url = new URL(data.html_url); } catch { return null; }
  const releasePrefix = '/ray-goldman/kayfabe/releases/tag/';
  let urlTag;
  try { urlTag = decodeURIComponent(url.pathname.slice(releasePrefix.length)); } catch { return null; }
  if (url.protocol !== 'https:' || url.hostname !== 'github.com' || url.username || url.password ||
      !url.pathname.startsWith(releasePrefix) || urlTag !== data.tag_name) return null;
  const version = data.tag_name.replace(/^v/, '');
  return { version, tag: data.tag_name, name: safeText(data.name) || data.tag_name, url: url.href };
}

function safeText(value) {
  if (typeof value !== 'string') return '';
  return value.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069\u{e0000}-\u{e007f}]/gu, ' ').trim().slice(0, 160);
}

async function checkForUpdate({ force = false } = {}) {
  const checkedAt = Date.now();
  if (!force && checkedAt - readCheckTime() < CHECK_INTERVAL_MS) {
    return { status: 'cached', currentVersion: pkg.version, release: null, reason: null };
  }
  // Record before contacting GitHub so an offline CLI does not wait on every invocation.
  const cacheWritable = recordCheckTime(checkedAt);
  if (!force && !cacheWritable) return unavailable('cache-unavailable');

  try {
    const response = await fetch(RELEASE_API, {
      headers: { accept: 'application/vnd.github+json', 'user-agent': 'kayfabe-release-check' },
      redirect: 'error',
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (response.status === 404) return unavailable('no-release');
    if (response.status === 403 || response.status === 429) return unavailable('rate-limited');
    if (!response.ok) return unavailable('http-error');

    const data = await response.json();
    const release = validRelease(data);
    const current = parseVersion(pkg.version);
    const latest = release && parseVersion(release.version);
    if (!release || !current || !latest) return unavailable('invalid-release');
    return compareVersions(latest, current) > 0
      ? { status: 'available', currentVersion: pkg.version, release, reason: null }
      : { status: 'current', currentVersion: pkg.version, release, reason: null };
  } catch {
    return unavailable('network-error');
  }
}

function npmInvocation(args) {
  if (process.platform !== 'win32') return { command: 'npm', args };

  const candidates = [
    process.env.npm_execpath,
    path.join(path.dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    path.join(process.env.ProgramFiles || 'C:\\Program Files', 'nodejs', 'node_modules', 'npm', 'bin', 'npm-cli.js'),
  ].filter((candidate) => typeof candidate === 'string' && candidate.endsWith('.js'));
  const npmCli = candidates.find((candidate) => {
    try { return fs.statSync(candidate).isFile(); } catch { return false; }
  });
  return npmCli ? { command: process.execPath, args: [npmCli, ...args] } : null;
}

function installRelease(release, { stdoutToStderr = false } = {}) {
  const parsed = release && parseVersion(release.version);
  const tagVersion = release && parseVersion(release.tag);
  if (!release || !parsed || !tagVersion || tagVersion.prerelease.length || compareVersions(parsed, tagVersion) !== 0) {
    return { ok: false, message: 'Refusing to install an invalid or non-stable release tag.' };
  }
  const invocation = npmInvocation([
    'install', '--global', '--no-audit', '--no-fund', '--ignore-scripts',
    `${INSTALL_REPO}#${release.tag}`,
  ]);
  if (!invocation) return { ok: false, message: 'Could not locate npm. Install npm and Git, then run kayfabe update again.' };

  const stdio = stdoutToStderr ? ['inherit', process.stderr, 'inherit'] : 'inherit';
  const result = spawnSync(invocation.command, invocation.args, { stdio, windowsHide: true });
  if (result.error) return { ok: false, message: `Could not run npm: ${result.error.message}` };
  if (result.status !== 0) return { ok: false, message: `npm update failed${result.status === null ? '' : ` (exit ${result.status})`}.` };
  return { ok: true, message: `Installed Kayfabe ${release.version}. Restart Kayfabe to use the new version.` };
}

async function promptForUpdate(release, options = {}) {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  try {
    const answer = await rl.question(`Install Kayfabe ${release.version} now? [y/N] `);
    if (!/^y(?:es)?$/i.test(answer.trim())) return { accepted: false, ok: true };
  } finally {
    rl.close();
  }
  return { accepted: true, ...installRelease(release, options) };
}

module.exports = { checkForUpdate, installRelease, promptForUpdate };
