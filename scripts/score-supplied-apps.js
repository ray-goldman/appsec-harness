'use strict';
// Static-only evaluator. Never loads JavaScript or other modules from a target.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { scan } = require('../src/engine');
const { toolHash } = require('../src/benchmark');
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const MARK = /(?:\/\/|#|\/\*|--|<!--)\s*BENCH\s+(vuln|safe)\s+(A\d\d)\s+CWE-(\d+)\s+([\w-]+)/;

function inventory(root) {
  const files = [];
  function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name, 'en'))) {
      const absolute = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) throw new Error('Target symlinks are unsupported');
      if (entry.isDirectory()) walk(absolute);
      else if (entry.isFile()) {
        if (files.length >= 1000 || fs.statSync(absolute).size > 1024 * 1024) throw new Error('Target inventory budget exceeded');
        const bytes = fs.readFileSync(absolute);
        files.push({ file: path.relative(root, absolute).replace(/\\/g, '/'), sha256: hash(bytes), text: bytes.toString('utf8') });
      }
    }
  }
  walk(root);
  return files;
}

function scoreLines(files, findings) {
  const cases = [];
  for (const file of files) {
    const lines = file.text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const m = lines[i].match(MARK);
      if (m) cases.push({ id: `${file.file}:${i + 1}:${m[4]}`, file: file.file, line: i + 2,
        vulnerable: m[1] === 'vuln', cwe: Number(m[3]), label: m[4], matches: [] });
    }
  }
  const unmatched = [];
  for (const f of findings) {
    // Only an exact CWE at the marked line or the next two lines is eligible.
    // Tied candidates are unscored; one finding never credits multiple labels.
    const candidates = cases.filter(c => c.file === f.file && f.cwe?.includes(c.cwe) &&
      f.line >= c.line && f.line <= c.line + 2).sort((a, b) => Math.abs(f.line - a.line) - Math.abs(f.line - b.line));
    if (!candidates.length || (candidates[1] && candidates[0].line === candidates[1].line)) {
      unmatched.push({ file: f.file, line: f.line, ruleId: f.ruleId, cwe: f.cwe });
    } else candidates[0].matches.push({ line: f.line, ruleId: f.ruleId });
  }
  const totals = { cases: cases.length, tp: 0, fp: 0, tn: 0, fn: 0 };
  for (const c of cases) {
    c.outcome = c.vulnerable ? (c.matches.length ? 'tp' : 'fn') : (c.matches.length ? 'fp' : 'tn');
    totals[c.outcome]++;
  }
  return { totals, cases, unmatched };
}

async function evaluate(root) {
  const files = inventory(root), apps = [];
  for (const name of fs.readdirSync(root).sort()) {
    if (!fs.statSync(path.join(root, name)).isDirectory()) continue;
    const appFiles = files.filter(f => f.file.startsWith(name + '/')).map(f => ({ ...f, file: f.file.slice(name.length + 1) }));
    const result = await scan(path.join(root, name), { includeTests: true });
    const scored = scoreLines(appFiles, result.findings);
    const extra = appFiles.find(f => f.file === 'bench.extra.json');
    apps.push({ app: name, findings: result.findings.length, ...scored,
      unscoredManifestLabels: extra ? JSON.parse(extra.text).items.length : 0 });
  }
  const totals = { cases: 0, tp: 0, fp: 0, tn: 0, fn: 0 };
  for (const app of apps) for (const key of Object.keys(totals)) totals[key] += app.totals[key];
  return { schema: 'appsec-harness/supplied-apps@1', measuredAt: new Date().toISOString(),
    sourceSha256: toolHash(), evaluatorSha256: hash(fs.readFileSync(__filename)),
    inputSha256: hash(JSON.stringify(files.map(({ file, sha256 }) => ({ file, sha256 })))),
    policy: { labels: 'User-supplied, unadjudicated; not independent accuracy evidence',
      matching: 'Exact file+CWE; finding at first line after marker or next two lines; nearest marker; one label per finding',
      manifestLabels: 'Unscored: package/CVE identity requires a separate adapter',
      unmatched: 'Unmatched findings are not assumed to be false positives' }, totals, apps };
}

if (require.main === module) {
  const [root, output] = process.argv.slice(2);
  if (!root || !output) throw new Error('Usage: node scripts/score-supplied-apps.js <apps directory> <output.json>');
  evaluate(path.resolve(root)).then(result => {
    fs.writeFileSync(output, JSON.stringify(result, null, 2) + '\n');
    console.log(JSON.stringify({ totals: result.totals, apps: result.apps.map(a => ({ app: a.app, ...a.totals, findings: a.findings })) }, null, 2));
  }).catch(error => { console.error(error.message); process.exitCode = 1; });
}
module.exports = { scoreLines, inventory, evaluate };
