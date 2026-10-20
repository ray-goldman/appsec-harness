'use strict';
const { CATEGORIES, cweLabel } = require('../owasp');

const ICON = { critical: '🟥', high: '🟧', medium: '🟨', low: '🟦', info: '⬜' };
const mdEsc = (s) => String(s || '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');

function toMarkdown(result, { gate } = {}) {
  const s = result.summary;
  const t = result.target;
  const out = [];
  out.push(`# AppSec report — ${t.name}`);
  out.push('');
  out.push(`- **Target:** \`${t.url || t.root}\`${t.commit ? ` @ \`${t.commit.slice(0, 12)}\`` : ''}${t.ref ? ` (ref \`${t.ref}\`)` : ''}`);
  out.push(`- **Scanned:** ${result.scannedAt} · ${result.stats.files} files · ${result.stats.dependencies} dependencies · ${result.stats.routes} routes · ${result.durationMs} ms`);
  out.push(`- **Harness:** appsec-harness ${result.tool.version}${result.triage ? ` · triaged by **${mdEsc(result.triage.reviewer)}**${result.triage.model ? ` (${mdEsc(result.triage.model)})` : ''}` : ' · not yet triaged'}`);
  if (gate) out.push(`- **Gate:** ${gate.passed ? '✅ PASS' : '❌ FAIL'} — ${gate.reason}`);
  out.push('');
  out.push(`| Severity | Open |`); out.push('|---|---|');
  for (const k of ['critical', 'high', 'medium', 'low', 'info']) out.push(`| ${ICON[k]} ${k} | ${s.bySeverity[k]} |`);
  out.push('');
  out.push('## OWASP Top 10:2025 coverage');
  out.push(''); out.push('| Category | Open | Crit | High | Med | Low |'); out.push('|---|---|---|---|---|---|');
  for (const [k, c] of Object.entries(s.byCategory)) out.push(`| [${k} ${c.name}](${CATEGORIES[k].url}) | ${c.total} | ${c.critical} | ${c.high} | ${c.medium} | ${c.low} |`);
  out.push('');
  if (result.warnings && result.warnings.length) { out.push('> **Warnings:** ' + result.warnings.map(mdEsc).join(' · ')); out.push(''); }

  const groups = {};
  for (const f of result.findings) (groups[f.owasp] = groups[f.owasp] || []).push(f);
  out.push('## Findings');
  for (const k of Object.keys(CATEGORIES)) {
    const fs = groups[k];
    if (!fs || !fs.length) continue;
    out.push(''); out.push(`### ${k}:2025 ${CATEGORIES[k].name} (${fs.length})`);
    for (const f of fs) {
      out.push('');
      const st = f.status !== 'open' ? ` · _${f.status}_` : '';
      const tri = f.triage ? ` · triage: **${f.triage.verdict}**` : '';
      out.push(`#### ${ICON[f.severity]} ${f.id} \`${f.ruleId}\` — ${mdEsc(f.title)}${st}${tri}`);
      out.push(`\`${f.file}:${f.line}\` · ${f.severity}/${f.confidence} · ${(f.cwe || []).map(cweLabel).join(', ')}${f.cves && f.cves.length ? ' · ' + f.cves.join(', ') : ''}${f.baseline === 'new' ? ' · 🆕 new since baseline' : ''}`);
      if (f.snippet) { out.push(''); out.push('```'); out.push(f.snippet); out.push('```'); }
      if (f.detail) out.push(`- Detail: ${mdEsc(f.detail)}`);
      if (f.taint) out.push(`- Data flow: \`${mdEsc(f.taint.source || f.taint.name || 'unknown')}\`${(f.taint.line || f.taint.from) ? ` (tainted at line ${f.taint.line || f.taint.from})` : ''} reaches this sink`);
      out.push(`- ${mdEsc(f.message)}`);
      out.push(`- **Fix:** ${mdEsc(f.fix)}`);
      if (f.triage) out.push(`- **Triage (${mdEsc(f.triage.verdict)}):** ${mdEsc(f.triage.rationale)}${f.triage.fix ? ' — ' + mdEsc(f.triage.fix) : ''}`);
      if (f.refs && f.refs.length) out.push(`- Refs: ${f.refs.slice(0, 3).map((r) => `<${r}>`).join(' ')}`);
    }
  }
  if (result.fixedSinceBaseline && result.fixedSinceBaseline.length) {
    out.push(''); out.push(`## Fixed since baseline (${result.fixedSinceBaseline.length})`);
    for (const f of result.fixedSinceBaseline) out.push(`- \`${f.ruleId}\` ${f.file}:${f.line} — ${mdEsc(f.title)}`);
  }
  if (result.surface && result.surface.length) {
    out.push(''); out.push(`## Attack surface (${result.surface.length} entry points)`);
    out.push(''); out.push('| Method | Path | Auth evidence | Location |'); out.push('|---|---|---|---|');
    for (const r of result.surface.slice(0, 300)) out.push(`| ${r.method} | \`${mdEsc(r.path)}\` | ${r.auth} | ${r.file}:${r.line} |`);
  }
  out.push('');
  return out.join('\n');
}

module.exports = { toMarkdown };
