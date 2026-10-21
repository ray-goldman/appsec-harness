'use strict';
// Hard-coded secret detection. Runs on raw text (comments included — secrets in comments still leak).
// Matched values are always redacted before they reach any report.
const { shannonEntropy } = require('../util');
const { scanDotnetSecrets } = require('../dotnet-secrets');

const PLACEHOLDER = /^(?:x+|\*+|\.+|0+|1234\w*|changeme|change_me|password|passw0rd|secret|example\w*|sample\w*|dummy\w*|test\w*|fake\w*|placeholder|your[_-]?\w+|<[^>]+>|\$\{[^}]+\}|\{\{[^}]+\}\}|%\(?\w+\)?s?|process\.env\.\w+|env\(.*\)|null|none|undefined|todo|redacted|xxx\w*|abc\w*|foo\w*|bar\w*|replace[_-]?me\w*|insert[_-]?\w+|\.\.\.)$/i;

const SECRET_PATTERNS = [
  { id: 'SECRET-AWS-001', title: 'AWS access key ID', re: /\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b/, severity: 'critical' },
  { id: 'SECRET-AWS-002', title: 'AWS secret access key', re: /aws_?secret_?(?:access_?)?key["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})\b/i, severity: 'critical' },
  { id: 'SECRET-GH-001', title: 'GitHub token', re: /\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b/, severity: 'critical' },
  { id: 'SECRET-GL-001', title: 'GitLab personal access token', re: /\b(glpat-[A-Za-z0-9_-]{20,})\b/, severity: 'critical' },
  { id: 'SECRET-SLACK-001', title: 'Slack token', re: /\b(xox[baprs]-[0-9A-Za-z-]{10,})\b/, severity: 'high' },
  { id: 'SECRET-SLACK-002', title: 'Slack incoming webhook', re: /(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]{20,})/, severity: 'medium' },
  { id: 'SECRET-DISCORD-001', title: 'Discord webhook', re: /(https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]{60,})/, severity: 'medium' },
  { id: 'SECRET-STRIPE-001', title: 'Stripe live secret key', re: /\b((?:sk|rk)_live_[0-9a-zA-Z]{20,})\b/, severity: 'critical' },
  { id: 'SECRET-GCP-001', title: 'Google API key', re: /\b(AIza[0-9A-Za-z_-]{35})\b/, severity: 'high' },
  { id: 'SECRET-GCP-002', title: 'GCP service account private key (JSON)', re: /"private_key"\s*:\s*"(-----BEGIN PRIVATE KEY-----[^"]{20,})/, severity: 'critical' },
  { id: 'SECRET-PK-001', title: 'Private key block', re: /(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)/, severity: 'critical' },
  { id: 'SECRET-NPM-001', title: 'npm access token', re: /\b(npm_[A-Za-z0-9]{36})\b/, severity: 'critical' },
  { id: 'SECRET-NPM-002', title: '.npmrc auth token', re: /_authToken\s*=\s*(?!\$\{)([A-Za-z0-9_\-.=]{20,})/, severity: 'critical' },
  { id: 'SECRET-PYPI-001', title: 'PyPI upload token', re: /\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,})\b/, severity: 'critical' },
  { id: 'SECRET-OPENAI-001', title: 'OpenAI API key', re: /\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,})\b/, severity: 'critical' },
  { id: 'SECRET-ANTHROPIC-001', title: 'Anthropic API key', re: /\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,})\b/, severity: 'critical' },
  { id: 'SECRET-TWILIO-001', title: 'Twilio API key', re: /\b(SK[0-9a-fA-F]{32})\b/, severity: 'high', context: /twilio/i },
  { id: 'SECRET-SENDGRID-001', title: 'SendGrid API key', re: /\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/, severity: 'high' },
  { id: 'SECRET-AZURE-001', title: 'Azure storage connection string', re: /(DefaultEndpointsProtocol=https?;AccountName=\w+;AccountKey=[A-Za-z0-9+/=]{40,})/, severity: 'critical' },
  { id: 'SECRET-JWT-001', title: 'Hard-coded JWT', re: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/, severity: 'medium' },
  { id: 'SECRET-DBURI-001', title: 'Database/broker URI with embedded password', re: /\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver):\/\/[^:\s/"'@]+:([^@\s"'$<{]{3,})@[^\s"']+)/i, severity: 'high', valueGroup: 2 },
];

// key = "value" style generic assignment.
const GENERIC = /(?<![\w.])([A-Za-z_][\w.-]*?(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|private[_-]?key|client[_-]?secret|signing[_-]?key|encryption[_-]?key)[A-Za-z_]*)["']?\s*(?:=|:|=>|:=)\s*["']([^"'\s]{6,})["']/i;

function scanSecrets(rel, raw, lines, opts = {}) {
  const findings = scanDotnetSecrets(rel, raw, lines, value => PLACEHOLDER.test(value));
  const isExampleFile = /\.(?:example|sample|template|dist)(?:\.|$)|(^|\/)(?:docs?|examples?)\//i.test(rel);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length > 4000) continue;
    for (const p of SECRET_PATTERNS) {
      const m = line.match(p.re);
      if (!m) continue;
      if (p.context && !p.context.test(raw)) continue;
      const value = m[p.valueGroup || 1];
      if (PLACEHOLDER.test(value)) continue;
      if (p.id === 'SECRET-PK-001') {
        // A header string alone (parsers, replace() calls) is not a key; require base64 key material.
        const after = line.slice(m.index + m[0].length);
        const next = lines[i + 1] || '';
        if (!/(?:\\n|\s)+[A-Za-z0-9+/]{40,}/.test(after) && !/^\s*["'`]?[A-Za-z0-9+/]{40,}={0,2}/.test(next) && !/^\s*Proc-Type:/.test(next)) continue;
      }
      findings.push({ ruleId: p.id, title: p.title, line: i + 1, col: m.index + 1, secret: value, severity: isExampleFile ? 'low' : p.severity });
    }
    const g = line.match(GENERIC);
    if (g) {
      const key = g[1], value = g[2];
      if (PLACEHOLDER.test(value)) continue;
      if (/^(?:true|false|\d+)$/i.test(value)) continue;
      if (/(?:_?(?:field|label|name|path|file|url|regex|pattern|type|length|min|max|policy|hint|prompt|placeholder|input|column|header|param|route|key_name))$/i.test(key)) continue;
      if (/\b(?:getenv|environ|process\.env|os\.Getenv|ENV\[|config\(|settings\.|System\.getenv)/.test(line)) continue;
      const ent = shannonEntropy(value);
      const weakDefault = /^(?:admin|root|password\d*|letmein|qwerty|123456\w*|secret\d*|changeit|default|guest|test123|keyboard ?cat)$/i.test(value);
      if (ent < 3.0 && !weakDefault) continue;
      findings.push({
        ruleId: weakDefault ? 'SECRET-DEFAULT-001' : 'SECRET-GENERIC-001',
        title: weakDefault ? 'Default / weak credential hard-coded' : 'Hard-coded credential or secret',
        line: i + 1, col: g.index + 1, secret: value, key,
        severity: isExampleFile ? 'low' : weakDefault ? 'high' : 'high',
        confidence: ent > 3.5 || weakDefault ? 'medium' : 'low',
      });
    }
  }
  return findings;
}

const SECRET_RULE_META = {
  owasp: 'A07', cwe: [798, 259, 540],
  message: 'A credential is committed to source control. Anyone with repository (or history) access — including every fork and CI log — can use it.',
  fix: 'Revoke/rotate the credential now, purge it from git history (git filter-repo), and load secrets from a secret manager or environment at runtime. Add pre-commit secret scanning.',
  refs: ['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'],
};

// Drop whole affected source lines before truncating. This handles multiple
// secrets and encoded literals without exposing partial values or raw syntax.
function redactSecretLines(rel, raw, lines, findings = scanSecrets(rel, raw, lines)) {
  const hidden = new Set();
  const values = new Set();
  for (const finding of findings) {
    for (const value of [finding.secret, ...(finding.redactValues || [])]) {
      if (value) { values.add(value); values.add(JSON.stringify(value).slice(1, -1)); }
    }
    if (values.size > 256) return lines.map(() => '[REDACTED: secret redaction budget exceeded]');
    let end = finding.endLine || finding.line;
    if (finding.ruleId === 'SECRET-PK-001') {
      // A detected PEM header authenticates the following body as secret text.
      // Missing/malformed footer: withhold the remaining file from context.
      end = lines.length;
      for (let line = finding.line - 1; line < lines.length; line++) {
        if (/-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----/.test(lines[line])) { end = line + 1; break; }
      }
    }
    for (let line = finding.line; line <= end; line++) hidden.add(line);
  }
  return lines.map((line, i) => hidden.has(i + 1) || (findings.length && /appsec-ignore/.test(line)) ||
    [...values].some(value => line.includes(value)) ? '[REDACTED: source line contains detected secret]' : line);
}
module.exports = { scanSecrets, redactSecretLines, SECRET_PATTERNS, SECRET_RULE_META };
