'use strict';
const fs = require('fs');
const path = require('path');
const { scan } = require('./engine');
const { clone } = require('./clone');
const { writeReports } = require('./report');
const { validateTriage, mergeTriage, gate, TRIAGE_SCHEMA } = require('./triage');
const { ALL, BY_ID, validateRules } = require('./rules');
const { CATEGORIES, cweLabel } = require('./owasp');
const ADVISORIES = require('./supply/advisories');
const { checkForUpdate, installRelease, promptForUpdate } = require('./update');
const pkg = require('../package.json');
const { coverageGate, coverageText } = require('./coverage');

const BOOL = new Set(['md', 'apply', 'claude', 'codex', 'include-tests', 'trust-suppressions', 'osv', 'include-vendored', 'dotnet-stored-data', 'dotnet-project-analysis', 'quiet', 'json', 'allow-ssh', 'allow-http', 'use-git-credentials', 'no-quarantine', 'new-only', 'verbose', 'help', 'no-gate', 'check', 'yes']);
BOOL.add('require-coverage');

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--') { args._.push(...argv.slice(i + 1)); break; }
    if (a.startsWith('--')) {
      const [k, v] = a.slice(2).split(/=(.*)/s);
      if (v !== undefined) args[k] = v;
      else if (BOOL.has(k)) args[k] = true;
      else if (i + 1 < argv.length && !argv[i + 1].startsWith('--')) args[k] = argv[++i];
      else args[k] = true;
    } else if (a === '-h') args.help = true;
    else args._.push(a);
  }
  return args;
}

const C = process.stdout.isTTY && !process.env.NO_COLOR ? { r: '\x1b[31m', y: '\x1b[33m', b: '\x1b[34m', g: '\x1b[32m', d: '\x1b[2m', B: '\x1b[1m', x: '\x1b[0m', m: '\x1b[35m' } : { r: '', y: '', b: '', g: '', d: '', B: '', x: '', m: '' };
const SEVC = { critical: C.r + C.B, high: C.r, medium: C.y, low: C.b, info: C.d };
const log = (...a) => process.stderr.write(a.join(' ') + '\n');

function updatesDisabled() {
  const value = String(process.env.KAYFABE_NO_UPDATE_CHECK || '').trim();
  return !!value && !/^(?:0|false|no)$/i.test(value);
}

async function maybePromptForUpdate(cmd, a) {
  if (!process.stdin.isTTY || !process.stderr.isTTY || updatesDisabled() || a.quiet ||
      ['help', 'version', 'update', 'mcp', 'selftest'].includes(cmd)) return;
  try {
    const result = await checkForUpdate();
    if (result.status !== 'available') return;
    log(`${C.y}Kayfabe ${result.release.version} is available (current: ${pkg.version}).${C.x}`);
    log(`Release notes: ${result.release.url}`);
    const choice = await promptForUpdate(result.release, { stdoutToStderr: true });
    if (!choice.accepted) return;
    if (choice.ok) log(`${C.g}${choice.message}${C.x}`);
    else log(`${C.y}${choice.message} Continuing with the current command.${C.x}`);
  } catch {
    // Update discovery and prompting must never prevent a normal scanner command.
  }
}

async function cmdUpdate(a) {
  if ((a.check && a.yes) || a._.length > 1) throw new Error('usage: kayfabe update [--check | --yes]');
  const result = await checkForUpdate({ force: true });
  if (result.status === 'unavailable') {
    if (result.reason === 'no-release') {
      log('No stable GitHub release is available yet.');
      return 0;
    }
    log(`Could not check GitHub for updates (${result.reason}).`);
    return 2;
  }
  if (result.status === 'current') {
    log(`Kayfabe ${pkg.version} is up to date.`);
    return 0;
  }
  if (result.status !== 'available') {
    log('GitHub update check did not return a current release.');
    return 2;
  }

  log(`Kayfabe ${result.release.version} is available (current: ${pkg.version}).`);
  log(`Release notes: ${result.release.url}`);
  if (a.check) return 0;

  let outcome;
  if (a.yes) outcome = { accepted: true, ...installRelease(result.release) };
  else if (process.stdin.isTTY && process.stderr.isTTY) outcome = await promptForUpdate(result.release);
  else {
    log('Run kayfabe update --yes to install this release.');
    return 0;
  }
  if (!outcome.accepted) {
    log('Update cancelled.');
    return 0;
  }
  log(outcome.message);
  return outcome.ok ? 0 : 2;
}

function stamp() { return new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19); }

function printSummary(result, g, written, cg = coverageGate(result)) {
  const s = result.summary;
  log(`\n${C.B}kayfabe ${pkg.version}${C.x} — ${result.target.name}${result.target.commit ? ' @ ' + result.target.commit.slice(0, 12) : ''}`);
  log(`${C.d}${result.stats.files} files · ${result.stats.dependencies} deps · ${result.stats.routes} routes · ${result.durationMs} ms${C.x}`);
  log(`${SEVC.critical}critical ${s.bySeverity.critical}${C.x}  ${SEVC.high}high ${s.bySeverity.high}${C.x}  ${SEVC.medium}medium ${s.bySeverity.medium}${C.x}  ${SEVC.low}low ${s.bySeverity.low}${C.x}  ${C.d}info ${s.bySeverity.info}${C.x}`);
  for (const [k, c] of Object.entries(s.byCategory)) if (c.total) log(`  ${k} ${c.name.padEnd(40)} ${String(c.total).padStart(4)}`);
  const top = result.findings.filter((f) => f.status === 'open').slice(0, 15);
  if (top.length) log('');
  for (const f of top) log(`  ${SEVC[f.severity]}${f.severity.padEnd(8)}${C.x} ${f.ruleId.padEnd(18)} ${f.file}:${f.line} ${C.d}${f.title}${C.x}`);
  if (result.summary.open > top.length) log(`  ${C.d}… ${result.summary.open - top.length} more${C.x}`);
  for (const w of result.warnings || []) log(`${C.y}warning:${C.x} ${w}`);
  log(coverageText(result));
  if (cg.required) log(`COVERAGE GATE ${cg.passed ? 'PASS' : 'FAIL'} — ${cg.reason}`);
  if (g) log(`\n${g.passed ? C.g + 'GATE PASS' : C.r + 'GATE FAIL'}${C.x} — ${g.reason}`);
  if (written) { log(''); for (const [k, p] of Object.entries(written)) log(`  ${C.d}${k.padEnd(20)}${C.x} ${p}`); }
}

function scanOpts(a) {
  return {
    includeTests: !!a['include-tests'], minConfidence: a['min-confidence'], minSeverity: a['min-severity'],
    trustSuppressions: !!a['trust-suppressions'], ignoreFile: a['ignore-file'], baseline: a.baseline, osv: !!a.osv, dotnetStoredData: !!a['dotnet-stored-data'], dotnetProjectAnalysis: !!a['dotnet-project-analysis'],
    includeVendored: !!a['include-vendored'], name: a.name, exclude: a.exclude ? String(a.exclude).split(',') : undefined, maxFileSize: a['max-file-size'] ? Number(a['max-file-size']) : undefined,
  };
}
const gateOpts = (a) => ({ failOn: a['fail-on'] || 'high', failConfidence: a['fail-confidence'] || 'medium', newOnly: !!a['new-only'] });

async function cmdScan(a, target, targetMeta) {
  if (!target) throw new Error('usage: kayfabe scan <path>');
  const result = await scan(target, { ...scanOpts(a), targetMeta, repoSymlinks: targetMeta && targetMeta.symlinks });
  const g = gate(result, gateOpts(a));
  const cg = coverageGate(result, !!a['require-coverage']);
  const outDir = a.out || path.join(process.cwd(), 'appsec-reports', `${result.target.name}-${stamp()}`);
  const formats = (a.format || 'all').split(',').map((s) => s.trim());
  const written = writeReports(result, outDir, { formats, gate: g, coverageGate: cg, failOn: gateOpts(a).failOn });
  if (a.json) process.stdout.write(JSON.stringify({ reportDir: outDir, files: written, summary: result.summary, gate: g, coverage: result.coverage, coverageGate: cg, passed: g.passed && cg.passed }, null, 2) + '\n');
  if (!a.quiet) printSummary(result, g, written, cg);
  return { result, gate: g, coverageGate: cg, outDir, written };
}

async function main(argv) {
  const a = parseArgs(argv);
  const cmd = a._[0];
  if (!cmd || a.help || cmd === 'help') return usage();
  await maybePromptForUpdate(cmd, a);

  switch (cmd) {
    case 'version': console.log(pkg.version); return 0;

    case 'update': return cmdUpdate(a);

    case 'scan': {
      const { gate: g, coverageGate: cg } = await cmdScan(a, a._[1]);
      return a['no-gate'] || (g.passed && cg.passed) ? 0 : 1;
    }

    case 'clone': {
      const meta = clone(a._[1], { ref: a.ref, dest: a.dest, allowSsh: a['allow-ssh'], allowHttp: a['allow-http'], useGitCredentials: a['use-git-credentials'], noQuarantine: a['no-quarantine'], workDir: a['work-dir'] });
      console.log(JSON.stringify(meta, null, 2));
      return 0;
    }

    case 'audit': {
      const t = a._[1];
      if (!t) throw new Error('usage: kayfabe audit <git-url|path> [--ref REF]');
      let target = t, meta;
      if (/^(?:https?|ssh):\/\/|^[\w.-]+@[\w.-]+:/.test(t)) {
        log(`${C.d}cloning ${t}${a.ref ? ' @ ' + a.ref : ''} (hardened, shallow)…${C.x}`);
        meta = clone(t, { ref: a.ref, dest: a.dest, allowSsh: a['allow-ssh'], allowHttp: a['allow-http'], useGitCredentials: a['use-git-credentials'], noQuarantine: a['no-quarantine'], workDir: a['work-dir'] });
        target = meta.path;
        if (meta.quarantined.length) log(`${C.m}quarantined ${meta.quarantined.length} agent/IDE config file(s): ${meta.quarantined.slice(0, 6).join(', ')}${meta.quarantined.length > 6 ? ', …' : ''}${C.x}`);
        if (meta.submodulesSkipped) log(`${C.y}note:${C.x} repository has submodules; they were not fetched.`);
        if (!a.name) a.name = path.basename(meta.path).replace(/-[a-z0-9]+$/, '');
      }
      const r = await cmdScan(a, target, meta && { url: meta.url, ref: meta.ref, commit: meta.commit, commitDate: meta.commitDate, quarantined: meta.quarantined });
      log(`\n${C.B}Next (agent triage):${C.x}\n  1. Read ${path.join(r.outDir, 'triage-request.json')}\n  2. Write ${path.join(r.outDir, 'triage.json')} (schema: kayfabe triage schema)\n  3. kayfabe triage validate ${r.outDir}\n  4. kayfabe report ${r.outDir}`);
      return a['no-gate'] || (r.gate.passed && r.coverageGate.passed) ? 0 : 1;
    }

    case 'triage': {
      const sub = a._[1];
      if (sub === 'schema') { console.log(JSON.stringify(TRIAGE_SCHEMA, null, 2)); return 0; }
      if (sub === 'validate') {
        const dir = a._[2]; if (!dir) throw new Error('usage: kayfabe triage validate <reportDir> [triage.json]');
        const result = JSON.parse(fs.readFileSync(path.join(dir, 'findings.json'), 'utf8'));
        const tfile = a._[3] || path.join(dir, 'triage.json');
        const tri = JSON.parse(fs.readFileSync(tfile, 'utf8'));
        const v = validateTriage(result, tri);
        console.log(JSON.stringify(v, null, 2));
        return v.ok ? 0 : 1;
      }
      throw new Error('usage: kayfabe triage <validate|schema>');
    }

    case 'report': {
      const dir = a._[1]; if (!dir) throw new Error('usage: kayfabe report <reportDir> [--triage triage.json]');
      let result = JSON.parse(fs.readFileSync(path.join(dir, 'findings.json'), 'utf8'));
      delete result.gate;
      const tfile = a.triage || path.join(dir, 'triage.json');
      if (fs.existsSync(tfile)) {
        const tri = JSON.parse(fs.readFileSync(tfile, 'utf8'));
        const v = validateTriage(result, tri);
        if (!v.ok) { console.log(JSON.stringify(v, null, 2)); log(`${C.r}triage invalid — fix errors above${C.x}`); return 2; }
        for (const w of v.warnings) log(`${C.y}warning:${C.x} ${w}`);
        result = mergeTriage(result, tri);
        log(`${C.d}merged triage from ${tri.reviewer}: ${v.coverage.triaged}/${v.coverage.open} findings (${v.coverage.percent}%)${C.x}`);
      }
      const g = gate(result, gateOpts(a));
      const cg = coverageGate(result, !!a['require-coverage']);
      const written = writeReports(result, dir, { formats: ['json', 'sarif', 'junit', 'md', 'html'], gate: g, coverageGate: cg, failOn: gateOpts(a).failOn, prefix: result.triage ? 'final-' : '' });
      if (!a.quiet) printSummary(result, g, written, cg);
      return a['no-gate'] || (g.passed && cg.passed) ? 0 : 1;
    }

    case 'gate': {
      const p = a._[1]; if (!p) throw new Error('usage: kayfabe gate <reportDir|findings.json>');
      const file = fs.statSync(p).isDirectory() ? (fs.existsSync(path.join(p, 'final-findings.json')) ? path.join(p, 'final-findings.json') : path.join(p, 'findings.json')) : p;
      const result = JSON.parse(fs.readFileSync(file, 'utf8'));
      const g = gate(result, gateOpts(a));
      const cg = coverageGate(result, !!a['require-coverage']);
      console.log(JSON.stringify({ ...g, coverageGate: cg, overallPassed: g.passed && cg.passed }, null, 2));
      return a['no-gate'] || (g.passed && cg.passed) ? 0 : 1;
    }

    case 'surface': {
      const result = await scan(a._[1] || '.', { minSeverity: 'info' });
      if (a.json) { console.log(JSON.stringify(result.surface, null, 2)); return 0; }
      for (const r of result.surface) console.log(`${r.method.padEnd(7)} ${r.path.padEnd(48)} ${r.auth.padEnd(8)} ${r.file}:${r.line}`);
      return 0;
    }

    case 'rules': {
      let rules = ALL;
      if (a.owasp) rules = rules.filter((r) => r.owasp === a.owasp.toUpperCase());
      if (a.lang) rules = rules.filter((r) => (r.languages || []).includes(a.lang));
      if (a.json) { console.log(JSON.stringify(rules.map((r) => ({ id: r.id, title: r.title, owasp: r.owasp, cwe: r.cwe, severity: r.severity, languages: r.languages })), null, 2)); return 0; }
      if (a.md) {
        const o = ['# Rule reference', '', `Generated by \`kayfabe rules --md\` — ${rules.length} rules, ${ADVISORIES.length} curated advisories. Every code rule has a vulnerable/fixed pair in \`corpus/\`.`, ''];
        for (const k of Object.keys(CATEGORIES)) {
          const rs = rules.filter((r) => r.owasp === k);
          o.push(`## ${k}:2025 ${CATEGORIES[k].name}`, '', `[OWASP page](${CATEGORIES[k].url}) · mapped CWEs: ${CATEGORIES[k].cwes.length}`, '', '| Rule | Title | Severity | CWE | Scope |', '|---|---|---|---|---|');
          for (const r of rs) o.push(`| \`${r.id}\` | ${r.title.replace(/\|/g, '\\|')} | ${r.severity} | ${r.cwe.map((c) => 'CWE-' + c).join(', ')} | ${(r.languages || []).join(', ') || (r.check ? 'config / project' : 'all files')} |`);
          o.push('');
        }
        console.log(o.join('\n'));
        return 0;
      }
      for (const k of Object.keys(CATEGORIES)) {
        const rs = rules.filter((r) => r.owasp === k);
        if (!rs.length) continue;
        console.log(`\n${C.B}${k}:2025 ${CATEGORIES[k].name}${C.x} (${rs.length})`);
        for (const r of rs) console.log(`  ${r.id.padEnd(22)} ${SEVC[r.severity]}${r.severity.padEnd(8)}${C.x} ${r.title} ${C.d}[${r.cwe.map((c) => 'CWE-' + c).join(',')}]${C.x}`);
      }
      const errs = validateRules(); if (errs.length) { log(errs.join('\n')); return 2; }
      console.log(`\n${rules.length} rules · ${ADVISORIES.length} curated advisories`);
      return 0;
    }

    case 'explain': {
      const id = (a._[1] || '').toUpperCase();
      if (CATEGORIES[id]) { const c = CATEGORIES[id]; console.log(`${id}:2025 ${c.name}\n${c.url}\nCWEs: ${c.cwes.map((x) => 'CWE-' + x).join(', ')}\nRules: ${ALL.filter((r) => r.owasp === id).map((r) => r.id).join(', ')}`); return 0; }
      const r = BY_ID.get(id);
      if (r) { console.log(`${r.id} — ${r.title}\n${r.owasp}:2025 ${CATEGORIES[r.owasp].name} · ${r.severity}\n${r.cwe.map(cweLabel).join(', ')}\n\n${r.message}\n\nFix: ${r.fix}\n\n${(r.refs || []).join('\n')}`); return 0; }
      const adv = ADVISORIES.filter((x) => x.ids.includes(id));
      if (adv.length) { for (const x of adv) console.log(`${x.ids.join(', ')} — ${x.eco}:${x.name}\n${x.summary}\nAffected: ${x.ranges.map((r) => r.versions ? r.versions.join(', ') : r.any ? 'all versions' : `>=${r.introduced} <${r.fixed}`).join('; ')}\n`); console.log('See docs/CVE-CATALOG.md for mechanism and detection notes.'); return 0; }
      throw new Error(`unknown id ${id} (try a rule id, CVE id or A01..A10)`);
    }

    case 'agent-setup': {
      const { spawnSync } = require('child_process');
      const bin = path.resolve(__dirname, '..', 'bin', 'kayfabe.js');
      const node = process.execPath;
      const which = (cmd) => spawnSync(process.platform === 'win32' ? 'where' : 'which', [cmd], { encoding: 'utf8' }).status === 0;
      const plans = [];
      if (!a.codex || a.claude) plans.push({ tool: 'claude', args: ['mcp', 'add', '--scope', 'user', 'appsec', '--', node, bin, 'mcp'] });
      if (!a.claude || a.codex) plans.push({ tool: 'codex', args: ['mcp', 'add', 'appsec', '--', node, bin, 'mcp'] });
      console.log('Register the kayfabe MCP server (absolute paths, works from any directory):\n');
      for (const p of plans) console.log(`  ${p.tool} ${p.args.map((x) => (/\s/.test(x) ? JSON.stringify(x) : x)).join(' ')}`);
      console.log(`\nCodex reads ${path.resolve(__dirname, '..', 'AGENTS.md')} when started in this directory; Claude Code reads CLAUDE.md and the /appsec-review skill.`);
      console.log('The CLI works without MCP: node bin/kayfabe.js audit <url> — see AGENTS.md §2.');
      if (a.apply) {
        for (const p of plans) {
          if (!which(p.tool)) { log(`${C.y}skip:${C.x} ${p.tool} not found on PATH`); continue; }
          const r = spawnSync(p.tool, p.args, { stdio: 'inherit' });
          log(r.status === 0 ? `${C.g}registered with ${p.tool}${C.x}` : `${C.r}${p.tool} mcp add failed (${r.status})${C.x}`);
        }
      } else console.log('\nRun with --apply to execute these commands.');
      return 0;
    }

    case 'benchmark': {
      const kind = a._[1], directory = a._[2];
      if (!directory) {
        throw new Error('usage: kayfabe benchmark <owasp-java|juliet-java|sard|cve-fixes|fetch-cve-fixes> <directory> [--out DIR] [--json]');
      }
      const opts = { expected: a.expected, manifest: a.manifest, localization: a.localization, revision: a['dataset-revision'], out: a.out };
      if (kind === 'fetch-cve-fixes') {
        const prepared = await require('./benchmark-cve').fetchCveCorpus(directory, opts);
        console.log(JSON.stringify(prepared, null, 2));
        return 0;
      }
      const adapters = {
        'owasp-java': ['./benchmark', 'runBenchmark'],
        'juliet-java': ['./benchmark-juliet', 'runJulietBenchmark'],
        sard: ['./benchmark-sard', 'runSardBenchmark'],
        'cve-fixes': ['./benchmark-cve', 'runCveBenchmark'],
      };
      if (!Object.hasOwn(adapters, kind)) throw new Error(`unknown benchmark dataset "${kind}"`);
      const [moduleName, method] = adapters[kind];
      const adapter = require(moduleName);
      const report = await adapter[method](directory, opts);
      console.log(a.json ? JSON.stringify(report, null, 2) : adapter.toMarkdown(report));
      return 0;
    }

    case 'selftest': return require('../test/corpus-runner').run({ verbose: !!a.verbose, json: !!a.json });

    case 'mcp': return require('./mcp/server').start();

    default: throw new Error(`unknown command "${cmd}" — run kayfabe help`);
  }
}

function usage() {
  console.log(`kayfabe ${pkg.version} — OWASP Top 10:2025 AppSec harness (zero dependencies)

  kayfabe audit <git-url|path> [--ref TAG|BRANCH|SHA]   clone (hardened) + scan + triage package
  kayfabe scan  <path>                                  scan a local directory
  kayfabe clone <git-url> [--ref REF] [--dest DIR]      hardened shallow clone only
  kayfabe triage schema | validate <reportDir> [file]   agent triage protocol
  kayfabe report <reportDir> [--triage triage.json]     merge triage → final-* reports
  kayfabe gate <reportDir|findings.json>                CI gate (exit 1 on failure)
  kayfabe surface <path> [--json]                       list HTTP entry points + auth evidence
  kayfabe rules [--owasp A05] [--lang python] [--json]  list rules
  kayfabe explain <RULE-ID|CVE-ID|A01..A10>
  kayfabe update [--check | --yes]                      check for or install a GitHub release
  kayfabe selftest [--verbose]                          run vulnerable/fixed regression corpus
  kayfabe benchmark owasp-java <directory>             measure independently labeled Java cases
  kayfabe benchmark juliet-java <directory>            measure Juliet Java good/bad regions
  kayfabe benchmark sard <directory>                   measure NIST SARD SARIF labels
  kayfabe benchmark fetch-cve-fixes <directory>         download pinned CVE source pairs (network)
  kayfabe benchmark cve-fixes <directory>               measure CVE parent/fix source pairs (offline)
  kayfabe mcp                                           MCP stdio server (Claude Code / Codex)
  kayfabe agent-setup [--claude|--codex] [--apply]      print/run MCP registration commands

scan/audit options:
  --out DIR               report directory (default ./appsec-reports/<name>-<time>)
  --format LIST           json,sarif,junit,md,html,triage | all (default all)
  --fail-on SEV           gate threshold: critical|high|medium|low (default high)
  --fail-confidence C     only gate on findings ≥ confidence (default medium)
  --min-confidence C      drop findings below confidence (default low)
  --min-severity S        drop findings below severity
  --include-tests         keep findings in test/fixture/example paths
  --baseline FILE         previous findings.json → mark new/existing, list fixed
  --new-only              gate only on findings new since baseline
  --ignore-file FILE      harness-side ignore list (fingerprint, reason, expires)
  --trust-suppressions    honour inline "appsec-ignore" comments in the target (off by default)
  --osv                   query osv.dev for every resolved dependency (sends name+version only)
  --dotnet-stored-data    opt in to low-confidence same-file stored-data XSS/raw-SQL checks
  --dotnet-project-analysis opt in to experimental C# method summaries and route-policy diagnostics
  --include-vendored      also scan node_modules/vendor/dist
  --exclude GLOBS         comma-separated paths/globs to skip (e.g. "docs,**/fixtures")
  --no-gate               always exit 0
  --require-coverage      also require selected source checks and complete Cargo inventory
update options:
  --check                 report the latest release without installing it
  --yes                   install the latest release without a prompt (explicit update command only)
  KAYFABE_NO_UPDATE_CHECK=1 disables automatic interactive checks
benchmark options:
  --expected FILE         label file relative to dataset (adapter-specific default)
  --manifest FILE         CVE corpus manifest (default bundled benchmarks/cve-fixes.json)
  --localization FILE     Reviewed CVE source-region labels (separate scoring policy)
  --dataset-revision SHA   declared full upstream commit SHA; input hashes are also recorded
  --out DIR               report directory outside dataset (default appsec-reports/benchmarks/<adapter>)
  --json                  print JSON instead of Markdown; both reports are written to disk
clone options: --allow-ssh --allow-http --use-git-credentials --no-quarantine --work-dir DIR
`);
  return 0;
}

module.exports = { main, parseArgs };
