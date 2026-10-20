'use strict';
// Untrusted-repo-safe file walker: never follows symlinks, caps depth/size/count, skips vendored trees.
const fs = require('fs');
const path = require('path');

const SKIP_DIRS = new Set([
  '.git', '.hg', '.svn', 'node_modules', 'bower_components', 'jspm_packages', 'vendor', 'third_party', 'third-party',
  '.venv', 'venv', 'env', '.tox', '.nox', '__pycache__', '.mypy_cache', '.pytest_cache', 'site-packages',
  'dist', 'build', 'out', 'target', '.next', '.nuxt', '.svelte-kit', '.output', 'coverage', '.nyc_output',
  '.gradle', '.idea', '.terraform', '.cache', '.parcel-cache', '.turbo', 'Pods', 'DerivedData', '.appsec-harness', '.kayfabe',
]);
const SKIP_FILE = /\.(?:min\.(?:js|css)|map|lock\.json\.bak|png|jpe?g|gif|webp|ico|bmp|tiff?|svgz|woff2?|ttf|eot|otf|mp[34]|mov|avi|webm|wav|flac|ogg|zip|tar|gz|tgz|bz2|xz|7z|rar|jar|war|ear|class|so|dylib|dll|exe|bin|o|a|pyc|pyo|wasm|pdf|docx?|xlsx?|pptx?|psd|ai|sketch|fig|sqlite3?|db|parquet|avro|pb|onnx|pt|pth|safetensors|h5|ckpt|npy|npz|pkl|iso|dmg|apk|ipa)$/i;

// Minimal glob: ** = any path, * = within a segment, ? = one char. A pattern also matches everything below it.
function globToRegExp(g) {
  const s = String(g).trim().replace(/^\.\//, '').replace(/\/$/, '');
  let re = '';
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '*' && s[i + 1] === '*') { re += '.*'; i++; if (s[i + 1] === '/') i++; }
    else if (c === '*') re += '[^/]*';
    else if (c === '?') re += '[^/]';
    else re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${re}(?:/.*)?$`);
}

function walk(root, opts = {}) {
  const maxFiles = opts.maxFiles || 50000;
  const maxDepth = opts.maxDepth || 40;
  const maxSize = opts.maxFileSize || 1024 * 1024;
  const includeVendored = !!opts.includeVendored;
  const excludes = (opts.exclude || []).filter(Boolean).map(globToRegExp);
  const excluded = (rel) => excludes.some((re) => re.test(rel));
  const files = [];
  const skipped = { large: 0, symlinks: [], binaryExt: 0, dirs: 0 };
  let javaIncomplete = false;
  const rootReal = fs.realpathSync(root);

  function visit(dirAbs, rel, depth) {
    if (depth > maxDepth || files.length >= maxFiles) { javaIncomplete = true; return; }
    let entries;
    try { entries = fs.readdirSync(dirAbs, { withFileTypes: true }); } catch { javaIncomplete = true; return; }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const e of entries) {
      if (files.length >= maxFiles) return;
      const abs = path.join(dirAbs, e.name);
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (excluded(r)) { skipped.excluded = (skipped.excluded || 0) + 1; javaIncomplete = true; continue; }
      if (e.isSymbolicLink()) {
        javaIncomplete = true;
        // Record symlinks; flag ones that escape the repo (CWE-59) — never follow them.
        let target = null;
        try { target = fs.readlinkSync(abs); } catch { /* ignore */ }
        const resolved = target ? path.resolve(path.dirname(abs), target) : null;
        const escapes = resolved && !resolved.startsWith(rootReal + path.sep) && resolved !== rootReal;
        skipped.symlinks.push({ rel: r, target, escapes });
        continue;
      }
      if (e.isDirectory()) {
        if (!includeVendored && SKIP_DIRS.has(e.name)) {
          skipped.dirs++;
          if (!['.git', '.hg', '.svn'].includes(e.name)) javaIncomplete = true;
          // Known-dangerous files that matter precisely because they ship inside vendor/.
          if (e.name === 'vendor') {
            for (const sub of ['phpunit/phpunit/src/Util/PHP/eval-stdin.php', 'phpunit/phpunit/Util/PHP/eval-stdin.php']) {
              const p = path.join(abs, ...sub.split('/'));
              try { const st = fs.lstatSync(p); if (st.isFile() && st.size < maxSize && fs.realpathSync(p).startsWith(rootReal + path.sep)) files.push({ rel: `${r}/${sub}`, abs: p, size: st.size }); } catch { /* absent */ }
            }
          }
          continue;
        }
        visit(abs, r, depth + 1);
        continue;
      }
      if (!e.isFile()) continue;
      if (SKIP_FILE.test(e.name)) { skipped.binaryExt++; continue; }
      let st;
      try { st = fs.lstatSync(abs); } catch { javaIncomplete = true; continue; }
      if (st.size > maxSize) { skipped.large++; if (/\.java(?:\.appsec-quarantined)?$/i.test(r)) javaIncomplete = true; continue; }
      files.push({ rel: r, abs, size: st.size });
    }
  }
  visit(root, '', 0);
  return { files, skipped, truncated: files.length >= maxFiles, javaIncomplete };
}

module.exports = { walk, SKIP_DIRS, globToRegExp };
