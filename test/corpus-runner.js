'use strict';
// Regression corpus: every case has vuln/ (must trigger all `expect` rules) and fixed/ (must trigger none of them).
// Reports per-OWASP-category recall and precision. Exit 1 on any regression.
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { scan } = require('../src/engine');
const { CATEGORIES } = require('../src/owasp');
const { sevRank } = require('../src/util');

const CORPUS = path.join(__dirname, '..', 'corpus');

// Secret-shaped values are generated at test time so the repository never contains token-format strings.
function generated(kind) {
  const pick = (alphabet, n) => Array.from(crypto.randomBytes(n), (b) => alphabet[b % alphabet.length]).join('');
  if (kind === 'aws') return 'AKIA' + pick('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', 16);
  if (kind === 'gh') return 'ghp_' + pick('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', 36);
  if (kind === 'pk') return '-----BEGIN ' + 'RSA PRIVATE KEY-----';
  if (kind === 'rlo') return String.fromCharCode(0x202e);
  if (kind === 'lri') return String.fromCharCode(0x2066);
  if (kind === 'pdi') return String.fromCharCode(0x2069);
  return 'x';
}

function stage(srcDir, gen) {
  const dest = fs.mkdtempSync(path.join(os.tmpdir(), 'appsec-corpus-'));
  const copy = (s, d) => {
    for (const e of fs.readdirSync(s, { withFileTypes: true })) {
      const sp = path.join(s, e.name), dp = path.join(d, e.name);
      if (e.isDirectory()) { fs.mkdirSync(dp, { recursive: true }); copy(sp, dp); continue; }
      let text = fs.readFileSync(sp, 'utf8');
      for (const [token, kind] of Object.entries(gen || {})) text = text.split(token).join(generated(kind));
      fs.writeFileSync(dp, text);
    }
  };
  copy(srcDir, dest);
  return dest;
}

async function runCase(dir) {
  const meta = JSON.parse(fs.readFileSync(path.join(dir, 'case.json'), 'utf8'));
  const out = { id: meta.id, owasp: meta.owasp, expect: meta.expect, missing: [], falsePositives: [], noise: [] };
  for (const kind of ['vuln', 'fixed']) {
    const tmp = stage(path.join(dir, kind), meta.generate);
    try {
      const r = await scan(tmp, { includeTests: true, minConfidence: 'low', name: `${meta.id}/${kind}` });
      const ids = new Set(r.findings.map((f) => f.ruleId));
      if (kind === 'vuln') out.missing = meta.expect.filter((e) => !ids.has(e));
      else {
        out.falsePositives = meta.expect.filter((e) => ids.has(e));
        out.noise = r.findings.filter((f) => !meta.expect.includes(f.ruleId) && sevRank(f.severity) >= 2 && f.confidence !== 'low').map((f) => `${f.ruleId}@${f.file}:${f.line}`);
      }
      if (kind === 'vuln') out.vulnFindings = r.findings.map((f) => `${f.ruleId}@${f.file}:${f.line}`);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  }
  out.pass = !out.missing.length && !out.falsePositives.length;
  return out;
}

async function run({ verbose = false, json = false, filter } = {}) {
  const dirs = fs.readdirSync(CORPUS).filter((d) => fs.existsSync(path.join(CORPUS, d, 'case.json'))).filter((d) => !filter || d.includes(filter)).sort();
  const results = [];
  for (const d of dirs) results.push(await runCase(path.join(CORPUS, d)));

  const cat = {};
  for (const k of Object.keys(CATEGORIES)) cat[k] = { cases: 0, tp: 0, fn: 0, fp: 0 };
  for (const r of results) {
    const c = cat[r.owasp];
    c.cases++;
    c.tp += r.expect.length - r.missing.length;
    c.fn += r.missing.length;
    c.fp += r.falsePositives.length;
  }
  let TP = 0, FN = 0, FP = 0;
  for (const c of Object.values(cat)) { TP += c.tp; FN += c.fn; FP += c.fp; }
  const pct = (a, b) => (b ? ((100 * a) / b).toFixed(1) + '%' : 'n/a');

  if (json) {
    console.log(JSON.stringify({ cases: results.length, passed: results.filter((r) => r.pass).length, recall: TP / (TP + FN), precision: TP / (TP + FP), byCategory: cat, results }, null, 2));
  } else {
    console.log(`\nRegression corpus — ${results.length} vulnerable/fixed case pairs\n`);
    console.log('Rules and cases were developed together. These metrics do not measure independent detection accuracy.\n');
    console.log('Category                                         cases  recall   precision');
    for (const [k, c] of Object.entries(cat)) {
      if (!c.cases) continue;
      console.log(`${(k + ' ' + CATEGORIES[k].name).padEnd(48)} ${String(c.cases).padStart(5)}  ${pct(c.tp, c.tp + c.fn).padStart(6)}   ${pct(c.tp, c.tp + c.fp).padStart(7)}`);
    }
    console.log(`${'TOTAL'.padEnd(48)} ${String(results.length).padStart(5)}  ${pct(TP, TP + FN).padStart(6)}   ${pct(TP, TP + FP).padStart(7)}\n`);
    for (const r of results) {
      if (!r.pass) {
        console.log(`FAIL ${r.id}`);
        if (r.missing.length) console.log(`     missed on vuln/: ${r.missing.join(', ')}   (got: ${r.vulnFindings.join(', ') || 'nothing'})`);
        if (r.falsePositives.length) console.log(`     fired on fixed/: ${r.falsePositives.join(', ')}`);
      } else if (verbose) console.log(`ok   ${r.id}`);
      if (verbose && r.noise.length) console.log(`     other findings on fixed/: ${r.noise.join(', ')}`);
    }
    const failed = results.filter((r) => !r.pass).length;
    console.log(failed ? `\n${failed} case(s) failed` : 'All cases passed.');
  }
  return results.every((r) => r.pass) ? 0 : 1;
}

if (require.main === module) {
  const a = process.argv.slice(2);
  run({ verbose: a.includes('--verbose'), json: a.includes('--json'), filter: a.find((x) => !x.startsWith('--')) }).then((c) => { process.exitCode = c; });
}

module.exports = { run, runCase };
