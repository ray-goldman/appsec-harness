'use strict';
// SARIF 2.1.0 — consumable by GitHub code scanning, GitLab, Azure DevOps, VS Code SARIF viewer.
const { BY_ID } = require('../rules');
const { CATEGORIES, cweLabel } = require('../owasp');

const LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
const SEC_SEV = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0', info: '1.0' };
const PRECISION = { high: 'high', medium: 'medium', low: 'low' };

function toSarif(result) {
  const used = [...new Set(result.findings.map((f) => f.ruleId))];
  const rules = used.map((id) => {
    const r = BY_ID.get(id) || { id, title: id, message: '', fix: '', cwe: [], owasp: 'A03', severity: 'medium' };
    const tags = ['security', `OWASP-${r.owasp}:2025`, ...(r.cwe || []).map((c) => `external/cwe/cwe-${c}`), ...(r.tags || [])];
    return {
      id, name: id.replace(/[^A-Za-z0-9]/g, ''),
      shortDescription: { text: r.title || id },
      fullDescription: { text: r.message || r.title || id },
      help: { text: `${r.message || ''}\n\nFix: ${r.fix || ''}`, markdown: `**${r.title}**\n\n${r.message || ''}\n\n**Fix:** ${r.fix || ''}\n\n${(r.cwe || []).map(cweLabel).join(', ')} · ${r.owasp}:2025 ${CATEGORIES[r.owasp] ? CATEGORIES[r.owasp].name : ''}\n\n${(r.refs || []).map((u) => `- ${u}`).join('\n')}` },
      helpUri: (r.refs && r.refs[0]) || (CATEGORIES[r.owasp] && CATEGORIES[r.owasp].url),
      defaultConfiguration: { level: LEVEL[r.severity] || 'warning' },
      properties: { tags, precision: PRECISION[r.confidence] || 'medium', 'security-severity': SEC_SEV[r.severity] || '5.5', 'problem.severity': LEVEL[r.severity] === 'error' ? 'error' : 'warning' },
    };
  });
  const ruleIndex = new Map(used.map((id, i) => [id, i]));
  const results = result.findings.filter((f) => f.status !== 'false_positive').map((f) => {
    const res = {
      ruleId: f.ruleId, ruleIndex: ruleIndex.get(f.ruleId),
      level: LEVEL[f.severity] || 'warning',
      message: { text: `${f.title}${f.detail ? ` (${f.detail})` : ''}. ${f.message}${f.taint ? ` [tainted: ${f.taint.source || f.taint.name || 'unknown'}${(f.taint.line || f.taint.from) ? ' from line ' + (f.taint.line || f.taint.from) : ''}]` : ''}` },
      locations: [{ physicalLocation: { artifactLocation: { uri: encodeURI(f.file), uriBaseId: 'SRCROOT' }, region: { startLine: f.line, startColumn: f.col || 1, snippet: f.snippet ? { text: f.snippet } : undefined } } }],
      partialFingerprints: { 'appsecFingerprint/v1': f.fingerprint },
      properties: { kind: f.kind || 'vulnerability', severity: f.severity, confidence: f.confidence, owasp: `${f.owasp}:2025`, cwe: (f.cwe || []).map((c) => `CWE-${c}`), cves: f.cves, context: f.context, findingId: f.id, triage: f.triage ? f.triage.verdict : undefined },
    };
    if (['suppressed', 'ignored', 'accepted'].includes(f.status)) {
      res.suppressions = [{ kind: f.status === 'suppressed' ? 'inSource' : 'external', status: 'accepted', justification: f.ignoreReason || (f.inlineSuppression && f.inlineSuppression.reason) || (f.triage && f.triage.rationale) || '' }];
    }
    return res;
  });
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'appsec-harness', version: result.tool.version, informationUri: 'https://owasp.org/Top10/2025/', semanticVersion: result.tool.version, rules } },
      originalUriBaseIds: { SRCROOT: { uri: 'file://' + encodeURI(result.target.root.replace(/\\/g, '/')) + '/' } },
      versionControlProvenance: result.target.url ? [{ repositoryUri: result.target.url, revisionId: result.target.commit }] : undefined,
      invocations: [{ executionSuccessful: true, endTimeUtc: result.scannedAt, toolExecutionNotifications: (result.warnings || []).map((w) => ({ level: 'warning', message: { text: w } })) }],
      results,
      properties: { summary: result.summary },
    }],
  };
}

module.exports = { toSarif };
