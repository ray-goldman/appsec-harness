'use strict';
const { CATEGORIES } = require('../owasp');
const { SECRET_PATTERNS, SECRET_RULE_META } = require('./secrets');
const { RULES: CONFIG_RULES } = require('./config');
const PROJECT_RULES = require('./project');

const CODE_RULES = [
  ...require('./javascript'),
  ...require('./python'),
  ...require('./php'),
  ...require('./java'),
  ...require('./go_ruby_csharp'),
  ...require('./csharp'),
];

const SUPPLY_RULES = [
  { id: 'SUPPLY-VULN-001', title: 'Dependency with known vulnerability (curated)', owasp: 'A03', cwe: [1395], severity: 'high', message: 'A dependency version is affected by a known CVE.', fix: 'Upgrade to a fixed version.', refs: ['https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/'] },
  { id: 'SUPPLY-OSV-001', title: 'Dependency with known vulnerability (OSV)', owasp: 'A03', cwe: [1395], severity: 'medium', message: 'OSV lists a vulnerability for this exact version.', fix: 'Upgrade to a fixed version.', refs: ['https://osv.dev/'] },
  { id: 'SUPPLY-MAL-001', title: 'Known-malicious package version', owasp: 'A03', cwe: [506], severity: 'critical', message: 'This exact version was published by an attacker (hijacked account, worm or sabotage).', fix: 'Remove it, rotate credentials on every machine/CI that installed it, check for persistence.', refs: ['https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/'] },
  { id: 'SUPPLY-SRC-001', title: 'Dependency installed from git/URL', owasp: 'A03', cwe: [829, 1357], severity: 'medium', message: 'Non-registry dependency source.', fix: 'Publish to a registry you control or pin to an immutable commit + integrity hash.', refs: ['https://docs.npmjs.com/cli/v10/configuring-npm/package-json#git-urls-as-dependencies'] },
  { id: 'SUPPLY-SRC-002', title: 'Insecure or unexpected package source', owasp: 'A03', cwe: [494, 829], severity: 'high', message: 'Packages fetched over HTTP or from an unexpected registry.', fix: 'Use HTTPS registries only and scope private registries.', refs: ['https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/'] },
  { id: 'SUPPLY-PIN-001', title: 'Wildcard / latest dependency version', owasp: 'A03', cwe: [1357], severity: 'medium', message: 'Any future (possibly malicious) version will be installed.', fix: 'Use exact or caret ranges with a committed lockfile.', refs: ['https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json'] },
  { id: 'SUPPLY-PIN-002', title: 'Unpinned Python requirements', owasp: 'A03', cwe: [1357], severity: 'low', message: 'Requirements are not pinned.', fix: 'Compile a lock with hashes (pip-compile --generate-hashes / uv lock).', refs: ['https://pip.pypa.io/en/stable/topics/secure-installs/'] },
  { id: 'SUPPLY-LOCK-001', title: 'No lockfile committed', owasp: 'A03', cwe: [1357], severity: 'low', message: 'Builds are not reproducible.', fix: 'Commit the lockfile and use `npm ci`.', refs: ['https://docs.npmjs.com/cli/v10/commands/npm-ci'] },
  { id: 'SUPPLY-SCRIPT-001', title: 'Dependencies with install scripts', owasp: 'A03', cwe: [494, 829], severity: 'info', message: 'Install scripts run arbitrary code during install.', fix: 'Install with `--ignore-scripts` in CI and allow-list packages that need scripts (e.g. via `npm config set ignore-scripts true` + explicit rebuild, or pnpm `onlyBuiltDependencies`).', refs: ['https://docs.npmjs.com/cli/v10/using-npm/scripts'] },
  { id: 'SUPPLY-SCRIPT-002', title: 'Lifecycle script downloads or evaluates code', owasp: 'A03', cwe: [494, 506], severity: 'high', message: 'Install hook fetches/executes remote code.', fix: 'Remove network access from lifecycle scripts.', refs: ['https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack'] },
  { id: 'SUPPLY-INTEGRITY-001', title: 'Lockfile entries missing integrity hashes', owasp: 'A08', cwe: [353, 494], severity: 'low', message: 'Integrity cannot be verified.', fix: 'Regenerate the lockfile with a current npm.', refs: ['https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json'] },
  { id: 'SUPPLY-INDEX-001', title: 'pip --extra-index-url (dependency confusion)', owasp: 'A03', cwe: [427, 829], severity: 'high', message: 'Mixed indexes allow public packages to shadow internal names.', fix: 'Use a single index that proxies PyPI (devpi/Artifactory) or `--index-url` only; pin with hashes.', refs: ['https://pytorch.org/blog/compromised-nightly-dependency/'] },
];

const SURFACE_RULES = [
  { id: 'FILE-SYMLINK-001', title: 'Symlink pointing outside the repository', owasp: 'A01', cwe: [59, 61], severity: 'medium', confidence: 'high', message: 'A committed symlink resolves outside the repo. Tools that follow it (archivers, static servers, CI caches, agents) can read or overwrite host files.', fix: 'Remove the symlink or make it relative within the repository.', refs: ['https://cwe.mitre.org/data/definitions/61.html'] },
  { id: 'AUTHZ-ROUTE-001', title: 'Route without visible auth guard', owasp: 'A01', cwe: [862, 285, 306], severity: 'medium', message: 'No authentication/authorization middleware, decorator or annotation is visible on this route. It may be protected elsewhere (global filter, gateway) — verify.', fix: 'Deny by default: apply auth middleware globally and explicitly mark public routes; enforce object-level authorization in the handler.', refs: ['https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html'] },
];

const SECRET_RULES = [
  ...SECRET_PATTERNS.map((p) => ({ id: p.id, title: p.title, severity: p.severity, ...SECRET_RULE_META })),
  { id: 'SECRET-GENERIC-001', title: 'Hard-coded credential or secret', severity: 'high', ...SECRET_RULE_META },
  { id: 'SECRET-DEFAULT-001', title: 'Default / weak credential hard-coded', severity: 'high', ...SECRET_RULE_META, cwe: [1392, 1393, 798] },
];

const ALL = [...CODE_RULES, ...CONFIG_RULES, ...PROJECT_RULES, ...SECRET_RULES, ...SUPPLY_RULES, ...SURFACE_RULES];
const BY_ID = new Map(ALL.map((r) => [r.id, r]));

function validateRules() {
  const errors = [];
  const seen = new Set();
  for (const r of ALL) {
    if (seen.has(r.id)) errors.push(`duplicate rule id ${r.id}`);
    seen.add(r.id);
    if (!CATEGORIES[r.owasp]) errors.push(`${r.id}: unknown OWASP category ${r.owasp}`);
    if (!Array.isArray(r.cwe) || !r.cwe.length) errors.push(`${r.id}: missing cwe`);
    if (!r.message || !r.fix) errors.push(`${r.id}: missing message/fix`);
    if (!['info', 'low', 'medium', 'high', 'critical'].includes(r.severity)) errors.push(`${r.id}: bad severity`);
  }
  return errors;
}

module.exports = { CODE_RULES, CONFIG_RULES, PROJECT_RULES, SECRET_RULES, SUPPLY_RULES, SURFACE_RULES, ALL, BY_ID, validateRules };
