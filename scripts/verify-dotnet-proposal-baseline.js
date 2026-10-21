'use strict';
// Reproduce the archived baseline's mixed LF/CRLF checkout without changing its
// code. Run only against a disposable checkout of the pinned harness commit.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const { walk } = require('../src/walker');
const root = path.resolve(__dirname, '..');
const output = path.join(root, 'appsec-out/claude-dotnet-review');
const baseline = path.join(output, 'baseline-check');
const commit = '3e0b67fe21d606e9b11f014eb6d660b6cffa0848';
const expected = '3f64530eeebf7085f0e4bc967ebdac79528933579d7d9ac4c1a5b25cafae69ee';
const git = args => execFileSync('git', args, { cwd: root, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 });
assert.equal(git(['-C', baseline, 'rev-parse', 'HEAD']).trim(), commit);
const lf = value => value.replace(/\r\n/g, '\n');
const files = ['package.json', ...['bin', 'src'].flatMap(dir =>
  walk(path.join(baseline, dir)).files.map(f => `${dir}/${f.rel}`))].sort();
const original = new Map(), data = new Map();
for (const file of files) {
  const text = lf(git(['show', `${commit}:${file}`]));
  assert.equal(lf(fs.readFileSync(path.join(baseline, file), 'utf8')), text, `modified baseline ${file}`);
  original.set(file, text);
}
const variants = ['package.json', 'src/csharp-checks.js', 'src/rules/config.js', 'src/rules/csharp.js', 'src/engine.js'];
for (const file of files) if (!variants.includes(file)) {
  const text = fs.readFileSync(path.join(root, file), 'utf8');
  assert.equal(lf(text), original.get(file), `unexpected current change ${file}`);
  data.set(file, text);
}
function digest(values) {
  const hash = crypto.createHash('sha256');
  for (const file of files) {
    const bytes = Buffer.from(values.get(file));
    hash.update(`${file}\0${bytes.length}\0`); hash.update(bytes);
  }
  return hash.digest('hex');
}
let found = false;
for (let bits = 0; bits < 2 ** variants.length; bits++) {
  variants.forEach((file, i) => data.set(file, bits & (1 << i) ? original.get(file).replace(/\n/g, '\r\n') : original.get(file)));
  if (digest(data) === expected) { found = true; break; }
}
assert.ok(found, 'Could not reproduce the original baseline byte hash');
for (const file of files) fs.writeFileSync(path.join(baseline, file), data.get(file));
const scorer = 'scripts/score-supplied-apps.js';
const scorerBytes = fs.readFileSync(path.join(root, scorer));
assert.equal(lf(scorerBytes.toString()), lf(git(['show', `${commit}:${scorer}`])));
fs.writeFileSync(path.join(baseline, scorer), scorerBytes);
assert.equal(require(path.join(baseline, 'src/benchmark')).toolHash(), expected);
require(path.join(baseline, scorer)).evaluate(path.join(output, 'benchmarks/apps/dotnet')).then(report => {
  fs.writeFileSync(path.join(output, 'before-verified.json'), JSON.stringify(report, null, 2) + '\n');
  fs.writeFileSync(path.join(output, 'baseline-verification.json'), JSON.stringify({
    gitCommit: commit, sourceSha256: expected, normalizedSourceSha256: digest(original), sourceFiles: files.length,
    verification: 'Every source file checked against the pinned Git blob after LF normalization; original byte hash reproduced using LF/CRLF variants; identical scorer rerun.',
  }, null, 2) + '\n');
  console.log('Verified pinned baseline source and rescored apps.');
}).catch(error => { console.error(error.message); process.exitCode = 1; });
