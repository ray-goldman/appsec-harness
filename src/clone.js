'use strict';
// Hardened git clone for untrusted repositories.
//  - https:// only by default (ssh opt-in); rejects file://, ext::, local paths and option-looking URLs
//  - hooks, fsmonitor, submodules, LFS smudge, symlink checkout and file/ext transports all disabled
//  - isolated from global/system git config unless --use-git-credentials
//  - shallow, single ref; nothing from the repo is ever executed
//  - agent auto-load files (CLAUDE.md, AGENTS.md, .claude/, .mcp.json, .vscode/…) are quarantined
const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const QUARANTINE_FILES = new Set(['CLAUDE.md', 'CLAUDE.local.md', 'AGENTS.md', 'AGENTS.override.md', 'GEMINI.md', '.cursorrules', '.windsurfrules', '.clinerules', '.mcp.json', 'copilot-instructions.md', '.aider.conf.yml']);
const QUARANTINE_DIRS = new Set(['.claude', '.codex', '.cursor', '.vscode', '.devcontainer', '.gemini', '.windsurf', '.continue']);
const SUFFIX = '.appsec-quarantined';

function validateUrl(url, { allowSsh = false, allowHttp = false } = {}) {
  if (typeof url !== 'string' || !url.trim()) throw new Error('repository URL required');
  if (/^-/.test(url)) throw new Error('refusing URL that starts with "-" (git option injection)');
  if (/[\s\0]/.test(url)) throw new Error('refusing URL with whitespace/control characters');
  if (/^(?:file|ext|fd)::?|^file:/i.test(url)) throw new Error('refusing file:// / ext:: transports');
  if (/^https:\/\/[^/\s]+\/.+/i.test(url)) return url;
  if (allowHttp && /^http:\/\/[^/\s]+\/.+/i.test(url)) return url;
  if (allowSsh && (/^ssh:\/\/[^/\s]+\/.+/i.test(url) || /^[\w.-]+@[\w.-]+:[\w./-]+$/.test(url))) return url;
  throw new Error(`unsupported repository URL "${url}" (https:// only; use --allow-ssh for git@host:org/repo)`);
}

function validateRef(ref) {
  if (ref == null) return null;
  if (!/^[\w][\w./+-]{0,200}$/.test(ref) || ref.includes('..') || /^-/.test(ref)) throw new Error(`invalid ref "${ref}"`);
  return ref;
}

function repoSlug(url) {
  const m = url.replace(/\.git$/, '').match(/[:/]([\w.-]+)\/([\w.-]+)$/);
  return m ? `${m[1]}-${m[2]}` : 'repo';
}

const HARDEN = [
  '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false', '-c', 'core.symlinks=false',
  '-c', 'core.protectNTFS=true', '-c', 'core.protectHFS=true', '-c', 'protocol.file.allow=never',
  '-c', 'protocol.ext.allow=never', '-c', 'submodule.recurse=false', '-c', 'transfer.fsckObjects=true',
  '-c', 'fetch.fsckObjects=true', '-c', 'filter.lfs.smudge=', '-c', 'filter.lfs.process=', '-c', 'filter.lfs.required=false',
  '-c', 'advice.detachedHead=false', '-c', 'credential.interactive=never', '-c', 'core.askPass=',
];

function git(args, { cwd, env, timeoutMs = 600000 }) {
  const r = spawnSync('git', [...HARDEN, ...args], { cwd, env, encoding: 'utf8', timeout: timeoutMs, maxBuffer: 64 * 1024 * 1024 });
  if (r.error) throw new Error(`git ${args[0]} failed: ${r.error.message}`);
  if (r.status !== 0) {
    const err = (r.stderr || '').trim();
    if (/could not read Username|Authentication failed|terminal prompts disabled|Repository not found/i.test(err)) throw new Error(`git ${args[0]}: repository not found or requires authentication. For private repos re-run with --use-git-credentials (uses your git credential helper).`);
    throw new Error(`git ${args[0]} failed (${r.status}): ${err.split('\n').slice(-3).join(' | ')}`);
  }
  return r.stdout;
}

function quarantine(root) {
  const moved = [];
  function visit(dir, inQDir, depth) {
    if (depth > 30) return;
    let entries; try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (e.name === '.git' || e.name === 'node_modules') continue;
      const abs = path.join(dir, e.name);
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) { visit(abs, inQDir || QUARANTINE_DIRS.has(e.name), depth + 1); continue; }
      if (!e.isFile() || e.name.endsWith(SUFFIX)) continue;
      if (inQDir || QUARANTINE_FILES.has(e.name)) {
        fs.renameSync(abs, abs + SUFFIX);
        moved.push(path.relative(root, abs).split(path.sep).join('/'));
      }
    }
  }
  visit(root, false, 0);
  return moved;
}

function clone(url, opts = {}) {
  validateUrl(url, opts);
  const ref = validateRef(opts.ref);
  const base = opts.workDir || path.join(os.tmpdir(), 'appsec-harness', 'work');
  fs.mkdirSync(base, { recursive: true, mode: 0o700 });
  const dest = opts.dest ? path.resolve(opts.dest) : path.join(base, `${repoSlug(url)}-${Date.now().toString(36)}`);
  if (fs.existsSync(dest) && fs.readdirSync(dest).length) throw new Error(`destination not empty: ${dest}`);
  fs.mkdirSync(dest, { recursive: true, mode: 0o700 });

  const env = {
    PATH: process.env.PATH, HOME: opts.useGitCredentials ? process.env.HOME : dest,
    GIT_TERMINAL_PROMPT: '0', GIT_LFS_SKIP_SMUDGE: '1', GIT_ASKPASS: '/bin/false', SSH_ASKPASS: '/bin/false',
    GIT_CONFIG_NOSYSTEM: '1', GIT_PROTOCOL_FROM_USER: '0', GIT_ALLOW_PROTOCOL: opts.allowSsh ? 'https:ssh' : (opts.allowHttp ? 'https:http' : 'https'),
    LANG: 'C', LC_ALL: 'C',
  };
  if (!opts.useGitCredentials) env.GIT_CONFIG_GLOBAL = '/dev/null';
  for (const k of ['HTTPS_PROXY', 'HTTP_PROXY', 'NO_PROXY', 'https_proxy', 'http_proxy', 'no_proxy', 'GIT_SSL_CAINFO', 'SSL_CERT_FILE', 'NODE_EXTRA_CA_CERTS', 'SSH_AUTH_SOCK']) if (process.env[k]) env[k] = process.env[k];
  if (process.env.SSL_CERT_FILE && !env.GIT_SSL_CAINFO) env.GIT_SSL_CAINFO = process.env.SSL_CERT_FILE;

  const isSha = ref && /^[0-9a-f]{7,40}$/i.test(ref);
  if (isSha) {
    git(['init', '-q', dest], { env });
    git(['remote', 'add', 'origin', url], { cwd: dest, env });
    git(['fetch', '-q', '--depth', '1', '--no-tags', '--no-recurse-submodules', 'origin', ref], { cwd: dest, env });
    git(['checkout', '-q', '--detach', 'FETCH_HEAD'], { cwd: dest, env });
  } else {
    const args = ['clone', '-q', '--depth', '1', '--single-branch', '--no-recurse-submodules', '--no-tags'];
    if (ref) args.push('--branch', ref);
    args.push('--', url, dest);
    git(args, { env });
  }

  const head = git(['rev-parse', 'HEAD'], { cwd: dest, env }).trim();
  let commitDate = null;
  try { commitDate = git(['log', '-1', '--format=%cI'], { cwd: dest, env }).trim(); } catch { /* ignore */ }
  // Symlinks are checked out as plain files (core.symlinks=false); recover them from the index for analysis.
  const symlinks = [];
  try {
    for (const l of git(['ls-files', '-s'], { cwd: dest, env }).split('\n')) {
      const m = l.match(/^120000 [0-9a-f]+ \d\t(.+)$/);
      if (!m) continue;
      let target = '';
      try { target = fs.readFileSync(path.join(dest, m[1]), 'utf8').trim(); } catch { /* ignore */ }
      symlinks.push({ rel: m[1], target, escapes: path.isAbsolute(target) || path.posix.normalize(path.posix.join(path.posix.dirname(m[1]), target)).startsWith('..') });
    }
  } catch { /* ignore */ }
  const submodules = fs.existsSync(path.join(dest, '.gitmodules'));
  const quarantined = opts.noQuarantine ? [] : quarantine(dest);

  const meta = { url: url.replace(/\/\/[^@/]+@/, '//***@'), ref: ref || null, commit: head, commitDate, path: dest, symlinks, submodulesSkipped: submodules, quarantined, clonedAt: new Date().toISOString() };
  fs.writeFileSync(`${dest}.appsec-clone.json`, JSON.stringify(meta, null, 2));
  return meta;
}

module.exports = { clone, validateUrl, validateRef, quarantine, QUARANTINE_FILES, QUARANTINE_DIRS, SUFFIX };
