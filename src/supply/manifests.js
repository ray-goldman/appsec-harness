'use strict';
// Dependency manifest / lockfile parsing + supply-chain hygiene checks (OWASP A03:2025).
// Parsers are intentionally forgiving: they extract (ecosystem, name, version, line) without executing anything.
const path = require('path');

const LOCKFILES = {
  npm: ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock'],
  pypi: ['poetry.lock', 'Pipfile.lock', 'uv.lock', 'pdm.lock'],
  composer: ['composer.lock'],
  rubygems: ['Gemfile.lock'],
  go: ['go.sum'],
};

const normPy = (n) => n.toLowerCase().replace(/[-_.]+/g, '-');

function lineOf(raw, needle, from = 0) {
  const idx = raw.indexOf(needle, from);
  if (idx < 0) return 1;
  let line = 1;
  for (let i = 0; i < idx; i++) if (raw.charCodeAt(i) === 10) line++;
  return line;
}

function safeJson(raw) { try { return JSON.parse(raw); } catch { return null; } }

// ---------------- parsers: return { deps: [...], hygiene: [...] } ----------------
function parsePackageJson(rel, raw) {
  const j = safeJson(raw); const deps = []; const hygiene = [];
  if (!j) return { deps, hygiene };
  for (const sect of ['dependencies', 'devDependencies', 'optionalDependencies']) {
    for (const [name, spec] of Object.entries(j[sect] || {})) {
      const line = lineOf(raw, `"${name}"`);
      if (typeof spec !== 'string') continue;
      if (/^(?:git(?:\+\w+)?:|github:|gitlab:|bitbucket:|https?:|file:|link:|[\w-]+\/[\w.-]+(?:#.*)?$)/.test(spec)) {
        hygiene.push({ ruleId: 'SUPPLY-SRC-001', line, severity: /^http:/.test(spec) ? 'high' : 'medium', detail: `${name} → ${spec}`,
          message: `Dependency \`${name}\` is installed from a URL/git ref instead of the registry: no registry provenance, integrity can change with the ref, and it bypasses advisory databases.` });
        continue;
      }
      if (/^(?:\*|latest|x|>=?\s*\d|"")$/.test(spec.trim()) || spec.trim() === '') {
        hygiene.push({ ruleId: 'SUPPLY-PIN-001', line, severity: 'medium', detail: `${name}@${spec}`, message: `\`${name}\` accepts any future version (\`${spec}\`). A hijacked publish is installed automatically.` });
      }
      deps.push({ eco: 'npm', name: name.toLowerCase(), spec, version: null, line, file: rel, direct: true, dev: sect === 'devDependencies' });
    }
  }
  const scripts = j.scripts || {};
  for (const k of ['preinstall', 'install', 'postinstall']) {
    if (scripts[k] && /\b(?:curl|wget|node\s+-e|eval|base64|\|\s*(?:ba)?sh|https?:\/\/)/.test(scripts[k])) {
      hygiene.push({ ruleId: 'SUPPLY-SCRIPT-002', line: lineOf(raw, `"${k}"`), severity: 'high', detail: `${k}: ${scripts[k].slice(0, 120)}`,
        message: `This package's own \`${k}\` script downloads or evaluates code — the pattern used by Shai-Hulud and similar worms.` });
    }
  }
  return { deps, hygiene };
}

function parsePackageLock(rel, raw) {
  const j = safeJson(raw); const deps = []; const hygiene = [];
  if (!j) return { deps, hygiene };
  const installScripts = []; let missingIntegrity = 0;
  if (j.packages) {
    for (const [key, p] of Object.entries(j.packages)) {
      if (!key || !p.version) continue;
      const name = (p.name || key.split('node_modules/').pop()).toLowerCase();
      const line = lineOf(raw, `"${key}"`);
      deps.push({ eco: 'npm', name, version: p.version, line, file: rel, direct: key.split('node_modules/').length === 2, dev: !!p.dev });
      if (p.hasInstallScript) installScripts.push(`${name}@${p.version}`);
      if (p.resolved && /^http:\/\//.test(p.resolved)) hygiene.push({ ruleId: 'SUPPLY-SRC-002', line, severity: 'high', detail: `${name} resolved over HTTP: ${p.resolved}`, message: 'Package tarball fetched over plain HTTP can be swapped in transit.' });
      else if (p.resolved && /^(?:git|https?:\/\/(?!registry\.npmjs\.org|registry\.yarnpkg\.com))/.test(p.resolved) && !p.link) hygiene.push({ ruleId: 'SUPPLY-SRC-002', line, severity: 'low', detail: `${name} → ${p.resolved.slice(0, 120)}`, message: 'Package resolved from a non-default registry or git. Confirm this source is intended (dependency confusion / substitution).' });
      if (p.resolved && !p.integrity && !p.link && !/^git/.test(p.resolved)) missingIntegrity++;
    }
  } else if (j.dependencies) {
    const walk = (obj, depth) => {
      for (const [name, p] of Object.entries(obj || {})) {
        if (p.version) deps.push({ eco: 'npm', name: name.toLowerCase(), version: p.version.replace(/^npm:.*@/, ''), line: lineOf(raw, `"${name}"`), file: rel, direct: depth === 0 });
        if (p.dependencies) walk(p.dependencies, depth + 1);
      }
    };
    walk(j.dependencies, 0);
  }
  if (installScripts.length) hygiene.push({ ruleId: 'SUPPLY-SCRIPT-001', line: 1, severity: 'info', detail: `${installScripts.length} package(s) run install scripts: ${installScripts.slice(0, 15).join(', ')}${installScripts.length > 15 ? ', …' : ''}`,
    message: 'Install scripts execute arbitrary code at `npm install` time with the developer\'s/CI\'s credentials. This is how most npm worms spread.' });
  if (missingIntegrity) hygiene.push({ ruleId: 'SUPPLY-INTEGRITY-001', line: 1, severity: 'low', detail: `${missingIntegrity} entries without integrity hash`, message: 'Lockfile entries without `integrity` cannot be verified on install.' });
  return { deps, hygiene };
}

function parseYarnLock(rel, raw) {
  const deps = []; const lines = raw.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const h = lines[i].match(/^"?((?:@[^@/"\s]+\/)?[^@"\s,]+)@/);
    if (!h || /^\s/.test(lines[i])) continue;
    for (let j = i + 1; j < Math.min(i + 8, lines.length); j++) {
      const v = lines[j].match(/^\s+version:?\s+"?([^"\s]+)"?/);
      if (v) { deps.push({ eco: 'npm', name: h[1].toLowerCase(), version: v[1], line: i + 1, file: rel }); break; }
    }
  }
  return { deps, hygiene: [] };
}

function parsePnpmLock(rel, raw) {
  const deps = []; const seen = new Set(); const lines = raw.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/^\s{2}['"]?\/?((?:@[^/@\s]+\/)?[^/@\s'"(]+)[@/](\d[^:'"(\s]*)(?:\([^)]*\))*['"]?:\s*$/);
    if (!m) continue;
    const k = `${m[1]}@${m[2]}`;
    if (seen.has(k)) continue; seen.add(k);
    deps.push({ eco: 'npm', name: m[1].toLowerCase(), version: m[2], line: i + 1, file: rel });
  }
  return { deps, hygiene: [] };
}

function parseRequirements(rel, raw) {
  const deps = []; const hygiene = []; const lines = raw.split('\n'); let unpinned = [];
  lines.forEach((l, i) => {
    const s = l.replace(/\s+#.*$/, '').trim();
    if (!s || s.startsWith('#')) return;
    if (/^--extra-index-url\b/.test(s)) hygiene.push({ ruleId: 'SUPPLY-INDEX-001', line: i + 1, severity: 'high', detail: s, message: '`--extra-index-url` merges indexes: pip picks the highest version from *any* index, so a public package with your internal name wins (dependency confusion — PyTorch torchtriton, Dec 2022).' });
    if (/^(?:--index-url|-i|--extra-index-url)\s+http:\/\//.test(s) || /^--trusted-host\b/.test(s)) hygiene.push({ ruleId: 'SUPPLY-SRC-002', line: i + 1, severity: 'high', detail: s, message: 'Packages fetched over HTTP or with TLS verification disabled.' });
    if (/^-/.test(s)) return;
    if (/^(?:git\+|https?:\/\/|\S+\s*@\s*(?:git\+|https?:))/.test(s)) { hygiene.push({ ruleId: 'SUPPLY-SRC-001', line: i + 1, severity: 'medium', detail: s, message: 'Dependency installed from a URL/VCS instead of the index.' }); return; }
    const m = s.match(/^([A-Za-z0-9][\w.-]*)(?:\[[^\]]*\])?\s*(===?|>=|~=|<=|!=|>|<)?\s*([\w.*+!-]+)?/);
    if (!m) return;
    const name = normPy(m[1]);
    if (m[2] === '==' || m[2] === '===') deps.push({ eco: 'pypi', name, version: m[3], line: i + 1, file: rel, direct: true });
    else { unpinned.push(name); deps.push({ eco: 'pypi', name, spec: (m[2] || '') + (m[3] || ''), version: null, line: i + 1, file: rel, direct: true }); }
  });
  if (unpinned.length) hygiene.push({ ruleId: 'SUPPLY-PIN-002', line: 1, severity: 'low', detail: `${unpinned.length} unpinned: ${unpinned.slice(0, 12).join(', ')}${unpinned.length > 12 ? ', …' : ''}`, message: 'Unpinned requirements resolve to whatever is newest at install time; builds are not reproducible and a malicious release is picked up automatically. Use a lock (pip-tools/uv/poetry) with hashes (`--require-hashes`).' });
  return { deps, hygiene };
}

function parsePipfileLock(rel, raw) {
  const j = safeJson(raw); const deps = [];
  if (!j) return { deps, hygiene: [] };
  for (const sect of ['default', 'develop']) for (const [n, p] of Object.entries(j[sect] || {})) {
    if (p.version) deps.push({ eco: 'pypi', name: normPy(n), version: p.version.replace(/^==/, ''), line: lineOf(raw, `"${n}"`), file: rel });
  }
  return { deps, hygiene: [] };
}

function parseTomlLock(rel, raw, eco) {
  const deps = []; const re = /\[\[package\]\]\s*\n\s*name\s*=\s*"([^"]+)"\s*\n\s*version\s*=\s*"([^"]+)"/g; let m;
  while ((m = re.exec(raw))) deps.push({ eco, name: eco === 'pypi' ? normPy(m[1]) : m[1], version: m[2], line: lineOf(raw, `name = "${m[1]}"`), file: rel });
  return { deps, hygiene: [] };
}

function parsePyproject(rel, raw) {
  const deps = [];
  const arr = raw.match(/^\s*dependencies\s*=\s*\[([\s\S]*?)\]/m);
  if (arr) for (const m of arr[1].matchAll(/["']([A-Za-z0-9][\w.-]*)(?:\[[^\]]*\])?\s*(==|>=|~=)?\s*([\w.]+)?/g)) {
    deps.push({ eco: 'pypi', name: normPy(m[1]), version: m[2] === '==' ? m[3] : null, spec: m[2] && m[2] !== '==' ? m[2] + m[3] : undefined, line: lineOf(raw, m[0]), file: rel, direct: true });
  }
  const poetry = raw.match(/\[tool\.poetry\.dependencies\]([\s\S]*?)(?:\n\[|$)/);
  if (poetry) for (const m of poetry[1].matchAll(/^\s*([A-Za-z0-9][\w.-]*)\s*=\s*["']([^"']+)["']/gm)) {
    if (m[1] === 'python') continue;
    deps.push({ eco: 'pypi', name: normPy(m[1]), version: /^\d/.test(m[2]) ? m[2] : null, spec: m[2], line: lineOf(raw, m[0]), file: rel, direct: true });
  }
  return { deps, hygiene: [] };
}

function parsePom(rel, raw) {
  const deps = []; const hygiene = [];
  const props = {};
  const pm = raw.match(/<properties>([\s\S]*?)<\/properties>/);
  if (pm) for (const m of pm[1].matchAll(/<([\w.-]+)>([^<]+)<\/\1>/g)) props[m[1]] = m[2].trim();
  const proj = raw.match(/<project[\s\S]*?<version>([^<]+)<\/version>/);
  if (proj) props['project.version'] = proj[1];
  const resolve = (v) => (v || '').replace(/\$\{([^}]+)\}/g, (_, k) => props[k] || `\${${k}}`).trim();
  for (const m of raw.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)) {
    const g = (m[1].match(/<groupId>([^<]+)<\/groupId>/) || [])[1];
    const a = (m[1].match(/<artifactId>([^<]+)<\/artifactId>/) || [])[1];
    const v = resolve((m[1].match(/<version>([^<]+)<\/version>/) || [])[1]);
    if (!g || !a) continue;
    deps.push({ eco: 'maven', name: `${g.trim()}:${a.trim()}`, version: v && !v.includes('${') ? v : null, line: lineOf(raw, `<artifactId>${a}</artifactId>`, m.index), file: rel, direct: true });
  }
  for (const m of raw.matchAll(/<(?:repository|pluginRepository)>[\s\S]*?<url>\s*(http:\/\/[^<]+)<\/url>/g)) {
    hygiene.push({ ruleId: 'SUPPLY-SRC-002', line: lineOf(raw, m[1]), severity: 'high', detail: m[1], message: 'Maven repository over plain HTTP (blocked by default since Maven 3.8.1) allows artifact substitution.' });
  }
  return { deps, hygiene };
}

function parseGradle(rel, raw) {
  const deps = [];
  for (const m of raw.matchAll(/["']([\w.-]+):([\w.-]+):([\w.+-]+)["']/g)) {
    deps.push({ eco: 'maven', name: `${m[1]}:${m[2]}`, version: /[+]|latest/.test(m[3]) ? null : m[3], spec: m[3], line: lineOf(raw, m[0]), file: rel, direct: true });
  }
  return { deps, hygiene: [] };
}

function parseGoMod(rel, raw) {
  const deps = []; const lines = raw.split('\n'); let inReq = false;
  lines.forEach((l, i) => {
    if (/^require\s*\(/.test(l)) { inReq = true; return; }
    if (inReq && /^\)/.test(l)) { inReq = false; return; }
    const m = inReq ? l.match(/^\s*([\w./-]+)\s+(v[\w.+-]+)/) : l.match(/^require\s+([\w./-]+)\s+(v[\w.+-]+)/);
    if (m) deps.push({ eco: 'go', name: m[1], version: m[2].replace(/^v/, '').replace(/\+incompatible$/, ''), line: i + 1, file: rel, direct: !/\/\/\s*indirect/.test(l) });
  });
  return { deps, hygiene: [] };
}

function parseGemfileLock(rel, raw) {
  const deps = []; const lines = raw.split('\n');
  lines.forEach((l, i) => { const m = l.match(/^ {4}([\w.-]+) \(([\w.]+)(?:-[\w-]+)?\)\s*$/); if (m) deps.push({ eco: 'rubygems', name: m[1], version: m[2], line: i + 1, file: rel }); });
  return { deps, hygiene: [] };
}

function parseComposerLock(rel, raw) {
  const j = safeJson(raw); const deps = [];
  if (!j) return { deps, hygiene: [] };
  for (const sect of ['packages', 'packages-dev']) for (const p of j[sect] || []) {
    deps.push({ eco: 'composer', name: p.name, version: String(p.version || '').replace(/^v/, ''), line: lineOf(raw, `"name": "${p.name}"`), file: rel, dev: sect === 'packages-dev' });
  }
  return { deps, hygiene: [] };
}

const PARSERS = [
  { re: /(^|\/)package\.json$/, fn: parsePackageJson, manifestFor: 'npm' },
  { re: /(^|\/)(?:package-lock|npm-shrinkwrap)\.json$/, fn: parsePackageLock },
  { re: /(^|\/)yarn\.lock$/, fn: parseYarnLock },
  { re: /(^|\/)pnpm-lock\.ya?ml$/, fn: parsePnpmLock },
  { re: /(^|\/)(?:requirements[\w.-]*|constraints[\w.-]*)\.(?:txt|in)$/, fn: parseRequirements },
  { re: /(^|\/)Pipfile\.lock$/, fn: parsePipfileLock },
  { re: /(^|\/)(?:poetry|uv|pdm)\.lock$/, fn: (r, raw) => parseTomlLock(r, raw, 'pypi') },
  { re: /(^|\/)pyproject\.toml$/, fn: parsePyproject, manifestFor: 'pypi' },
  { re: /(^|\/)pom\.xml$/, fn: parsePom },
  { re: /(^|\/)build\.gradle(?:\.kts)?$/, fn: parseGradle },
  { re: /(^|\/)go\.mod$/, fn: parseGoMod },
  { re: /(^|\/)Gemfile\.lock$/, fn: parseGemfileLock },
  { re: /(^|\/)composer\.lock$/, fn: parseComposerLock },
];

function isManifest(rel) { return PARSERS.some((p) => p.re.test(rel)); }

function parseManifest(rel, raw) {
  for (const p of PARSERS) if (p.re.test(rel)) return { ...p.fn(rel, raw), manifestFor: p.manifestFor };
  return null;
}

module.exports = { parseManifest, isManifest, LOCKFILES, normPy };
