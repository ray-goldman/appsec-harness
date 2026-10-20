'use strict';
// JUnit XML: one <testsuite> per OWASP Top 10:2025 category. Every category always emits at least one
// testcase, so CI dashboards show "A05 Injection: passed" rather than an empty suite.
// Open findings ≥ threshold → <failure>; below threshold → passing case with system-out;
// false positives / accepted / suppressed → <skipped>.
const { CATEGORIES } = require('../owasp');
const { sevRank } = require('../util');

const esc = (s) => String(s == null ? '' : s).replace(/[<>&'"]/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', "'": '&apos;', '"': '&quot;' }[c])).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, '');

function toJUnit(result, { failOn = 'high' } = {}) {
  const threshold = sevRank(failOn);
  const suites = [];
  let totalTests = 0, totalFail = 0, totalSkip = 0;
  for (const [code, cat] of Object.entries(CATEGORIES)) {
    const fs = result.findings.filter((f) => f.owasp === code);
    const cases = [];
    let failures = 0, skipped = 0;
    if (!fs.length) cases.push(`    <testcase classname="${esc(`owasp.${code}`)}" name="${esc(`${code}:2025 ${cat.name} — no findings`)}" time="0"/>`);
    for (const f of fs) {
      const name = `[${f.severity.toUpperCase()}] ${f.ruleId} ${f.file}:${f.line}`;
      const body = `${f.title}\n${f.message}\nFix: ${f.fix}\n${f.snippet ? 'Code: ' + f.snippet + '\n' : ''}CWE: ${(f.cwe || []).join(', ')}  Confidence: ${f.confidence}  Fingerprint: ${f.fingerprint}${f.triage ? `\nTriage: ${f.triage.verdict} — ${f.triage.rationale}` : ''}`;
      let inner = '';
      if (['false_positive', 'accepted', 'suppressed', 'ignored'].includes(f.status)) { inner = `<skipped message="${esc(f.status + (f.triage ? ': ' + f.triage.rationale : ''))}"/>`; skipped++; }
      else if (sevRank(f.severity) >= threshold) { inner = `<failure type="${esc(f.ruleId)}" message="${esc(f.title)}">${esc(body)}</failure>`; failures++; }
      else inner = `<system-out>${esc(body)}</system-out>`;
      cases.push(`    <testcase classname="${esc(`owasp.${code}.${f.ruleId}`)}" name="${esc(name)}" file="${esc(f.file)}" line="${f.line}" time="0">${inner}</testcase>`);
    }
    totalTests += cases.length; totalFail += failures; totalSkip += skipped;
    suites.push(`  <testsuite name="${esc(`${code}:2025 ${cat.name}`)}" tests="${cases.length}" failures="${failures}" errors="0" skipped="${skipped}" timestamp="${esc(result.scannedAt)}">\n${cases.join('\n')}\n  </testsuite>`);
  }
  return `<?xml version="1.0" encoding="UTF-8"?>\n<testsuites name="appsec-harness ${esc(result.target.name)}" tests="${totalTests}" failures="${totalFail}" errors="0" skipped="${totalSkip}">\n${suites.join('\n')}\n</testsuites>\n`;
}

module.exports = { toJUnit };
