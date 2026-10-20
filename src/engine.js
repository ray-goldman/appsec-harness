'use strict';
const fs = require('fs');
const path = require('path');
const { walk } = require('./walker');
const { detectLanguage, stripComments, analyzeTaint, maskStrings, SANITIZERS } = require('./languages');
const { CODE_RULES, CONFIG_RULES, PROJECT_RULES, BY_ID } = require('./rules');
const { scanSecrets } = require('./rules/secrets');
const { analyzeSupplyChain, queryOsv } = require('./supply');
const { isManifest } = require('./supply/manifests');
const { extractRoutes, routeFindings } = require('./surface');
const { CATEGORIES } = require('./owasp');
const { sha256, sevRank, confRank, isProbablyBinary, isTestPath, redact, truncate } = require('./util');
const pkg = require('../package.json');
const { constantSinkFilter } = require('./java-constants');
const { buildJavaProjectIndex } = require('./java-project');
const { javaOutputFilter } = require('./java-sanitizers');
const { buildScriptProject, scriptSinkFilter } = require('./script-helpers');

const MAX_LINE = 2000;
const WRAPPED = new RegExp('^\\s*(?:await\\s+)?' + SANITIZERS.source.replace(/^\\\\b/, '') + '[\\s\\S]*\\)\\s*$', 'i');

// Join continuation lines when a call's parentheses are unbalanced (multi-line arguments).
function windowAt(lines, i) {
  let w = lines[i];
  let bal = 0;
  for (const ch of w) { if (ch === '(') bal++; else if (ch === ')') bal--; }
  let j = i + 1;
  while (bal > 0 && j < lines.length && j <= i + 6) {
    const nx = lines[j];
    if (nx.length > MAX_LINE) break;
    for (const ch of nx) { if (ch === '(') bal++; else if (ch === ')') bal--; }
    w += '\n' + nx; j++;
  }
  return w;
}

// Third-party front-end bundles copied into a repo (jquery, bootstrap, materialize…): pattern rules on
// library internals are noise; their risk is covered as a component (A03) instead.
const VENDOR_NAME = /(?:^|\/)(?:jquery|bootstrap|materialize|angular|react(?:-dom)?|vue|lodash|underscore|backbone|moment|d3|chart|popper|foundation|semantic|select2|datatables|highlight|prism|codemirror|ace|tinymce|ckeditor|three|socket\.io|handlebars|mustache|knockout|ember|modernizr|swagger-ui|pdf|fontawesome|leaflet|plotly|echarts|hammer|velocity|alpine|htmx|zepto|require|sweetalert2?|toastr|dropzone|summernote|quill|marked|showdown|dompurify|axios|bluebird|q|rxjs|polyfill)[\w.-]*\.(?:m?js|css)$/i;
const VENDOR_DIR = /(?:^|\/)(?:static|public|assets|web|www|wwwroot|resources)\/(?:.*\/)?(?:vendor|vendors|lib|libs|plugins|external|third[-_]?party|bower)\//i;
function isVendoredAsset(rel, text) {
  if (!/\.(?:m?js|css)$/i.test(rel)) return false;
  if (VENDOR_NAME.test(rel) || VENDOR_DIR.test(rel)) return true;
  return text.length > 30000 && /^\s*\/\*[!*][\s\S]{0,600}?(?:@license|\(c\)|copyright|licensed under|MIT License|\bv?\d+\.\d+\.\d+\b)/i.test(text.slice(0, 1200));
}

// Split call arguments starting just after the opening paren; stops at the matching close paren.
function callArgs(text, start) {
  const args = [];
  let depth = 0, q = null, last = start;
  for (let i = start; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === '\\') { i++; continue; } if (c === q) q = null; continue; }
    if (c === '"' || c === "'" || c === '`') { q = c; continue; }
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') { if (depth === 0) { args.push(text.slice(last, i)); return args; } depth--; }
    else if (c === ',' && depth === 0) { args.push(text.slice(last, i)); last = i + 1; }
  }
  args.push(text.slice(last));
  return args;
}
function firstArg(text, start) { return callArgs(text, start)[0]; }

function sinksOf(rule) {
  if (rule.taintSinks) return rule.taintSinks;
  if (rule.taintSink) return [{ re: rule.taintSink, arg: rule.taintArg || 'first' }];
  return [];
}

function applyCodeRules(file, lang, raw, codeLines, taint, javaProject, scriptProject) {
  const out = [];
  const rawLines = raw.split(/\r?\n/);
  const code = codeLines.join('\n');
  const maskedLines = maskStrings(code, lang).split('\n'); // file-level: knows about multi-line strings/docstrings
  const windows = new Array(codeLines.length);
  const constantJavaSink = lang === 'java' ? constantSinkFilter(code, callArgs, raw, { file, project: javaProject }) : null;
  const javaOutput = constantJavaSink ? javaOutputFilter({ code, filter: constantJavaSink, project: javaProject }) : null;
  const javaStrictTaint = lang === 'java' ? analyzeTaint(codeLines, lang, { genericSanitizers: false }) : null;
  const javaNonHtmlTaint = lang === 'java' ? analyzeTaint(codeLines, lang, { rejectHtmlSanitizers: true }) : null;
  const scriptProof = ['javascript', 'python'].includes(lang) ? scriptSinkFilter(file, scriptProject, callArgs) : null;
  const win = (i) => (windows[i] === undefined ? (windows[i] = windowAt(codeLines, i)) : windows[i]);
  for (const rule of CODE_RULES) {
    if (!rule.languages.includes(lang)) continue;
    if (rule.files && !rule.files.test(file)) continue;
    if (rule.fileRequires && !rule.fileRequires.test(code)) continue;
    if (rule.fileExcludes && rule.fileExcludes.test(code)) continue;
    const contextualJavaOutput = lang === 'java' && rule.id === 'JAVA-XSS-001';
    const ruleTaint = contextualJavaOutput ? javaStrictTaint : javaNonHtmlTaint || taint;
    if (rule.checkCode) {
      for (const hit of rule.checkCode({ file, lang, raw, code, codeLines, maskedLines, taint })) {
        out.push({ ...hit, ruleId: rule.id, file, source: 'sast' });
      }
      continue;
    }
    const sinks = sinksOf(rule);
    for (let i = 0; i < codeLines.length; i++) {
      const L = codeLines[i];
      if (!L || L.length > MAX_LINE || !L.trim()) continue;
      const W = win(i);
      if (!contextualJavaOutput && rule.notLine && rule.notLine.test(W)) continue;
      if (rule.rawNotLine && rule.rawNotLine.test(rawLines[i] || '')) continue;
      let hit = null;
      // A match that *starts* inside a string literal is text, not code (e.g. an error message mentioning eval()).
      const ML = maskedLines[i] || '';
      const startsInString = (idx) => !rule.inString && idx < L.length && ML[idx] !== L[idx] && !/["'`]/.test(L[idx]);
      if (rule.pattern) {
        const m = W.match(rule.pattern);
        if (m && m.index < L.length && !startsInString(m.index + (m[0].length - m[0].trimStart().length))) {
          const t = ruleTaint.lineTainted(W);
          if (!(rule.requireTaint && !t)) {
            let ok = true;
            if (rule.nextLine) {
              const after = L.slice(L.lastIndexOf(':') + 1).trim();
              if (!after) {
                let j = i + 1; while (j < codeLines.length && !codeLines[j].trim()) j++;
                ok = j < codeLines.length && rule.nextLine.test(codeLines[j]);
              }
            }
            if (ok) hit = { col: m.index + 1, confidence: t ? 'high' : rule.confidence, taint: t };
          }
        }
      }
      if (!hit) {
        for (const s of sinks) {
          const re = new RegExp(s.re.source, s.re.flags.replace(/[gy]/g, '') + 'g');
          const matches = contextualJavaOutput ? [...W.matchAll(re)] : [re.exec(W)].filter(Boolean);
          for (const m of matches) {
            if (m.index >= L.length || startsInString(m.index)) continue;
            const after = m.index + m[0].length;
            const isCall = /\($/.test(m[0].replace(/\s+$/, ''));
            let args = isCall ? callArgs(W, after) : [W.slice(after)];
            if (s.arg !== 'all') args = args.slice(0, 1);
            let t = null;
            for (const arg of args) {
              if (!contextualJavaOutput && WRAPPED.test(arg) &&
                  !(lang === 'java' && /\b(?:forHtml|forHtmlContent|encodeForHTML|htmlEscape|escapeHtml|escapeHtml4)\s*\(/.test(arg))) continue;
              t = ruleTaint.lineTainted(arg);
              if (t) break;
            }
            if (t) { hit = { col: m.index + 1, confidence: 'high', taint: t }; break; }
          }
          if (hit) break;
        }
      }
      if (hit) {
        if (scriptProof && scriptProof(rule.id, i, W)) continue;
        if (contextualJavaOutput && javaOutput(i, W)) continue;
        if (constantJavaSink && ['JAVA-SQLI-001', 'JAVA-SQLI-002', 'JAVA-CMDI-001', 'JAVA-REDIRECT-001'].includes(rule.id)
          && (rule.id === 'JAVA-SQLI-002'
            ? constantJavaSink.sqlAssembly(i, W, rule.pattern, BY_ID.get('JAVA-SQLI-001').taintSink)
            : constantJavaSink(i, W, rule.taintSink, rule.taintArg === 'all'))) continue;
        let severity;
        if (hit.taint && rule.severityIfTainted) severity = rule.severityIfTainted;
        if (rule.escalate && rule.escalate.re.test(W)) severity = rule.escalate.severity;
        out.push({ ruleId: rule.id, file, line: i + 1, col: hit.col, confidence: hit.confidence, severity, taint: hit.taint || undefined, source: 'sast' });
      }
    }
  }
  return out;
}

function applyConfigRules(file, lang, raw, rawLines, codeLines) {
  const out = [];
  for (const rule of CONFIG_RULES) {
    let applies = false;
    try { applies = rule.appliesTo(file, lang, raw); } catch { applies = false; }
    if (!applies) continue;
    let hits = [];
    try { hits = rule.check({ rel: file, raw, lines: rawLines, code: codeLines, lang }) || []; } catch (e) { hits = []; }
    for (const h of hits) out.push({ ruleId: rule.id, file, line: h.line, col: h.col || 1, detail: h.detail, severity: h.severityOverride, source: 'config' });
  }
  return out;
}

const SUPPRESS_RE = /appsec-ignore(?:\s*[:=]?\s*([A-Z][A-Z0-9-]+(?:\s*,\s*[A-Z][A-Z0-9-]+)*))?(?:\s*[-:]\s*(.+))?/;

function loadIgnoreFile(p) {
  if (!p) return [];
  const j = JSON.parse(fs.readFileSync(p, 'utf8'));
  return (j.ignores || []).map((x) => ({ ...x, expired: x.expires ? new Date(x.expires) < new Date() : false }));
}

function fingerprintAll(findings, lineText) {
  const counts = new Map();
  for (const f of findings) {
    const norm = (lineText(f) || '').replace(/\s+/g, ' ').trim();
    const base = `${f.ruleId}|${f.file}|${norm}|${f.detail || ''}`;
    const n = (counts.get(base) || 0) + 1; counts.set(base, n);
    f.fingerprint = sha256(`${base}|${n}`).slice(0, 16);
  }
}

/**
 * Scan a directory. Never executes anything from the target.
 * opts: { includeTests, minConfidence, minSeverity, trustSuppressions, ignoreFile, baseline, osv, maxFileSize, includeVendored, name, quarantined }
 */
async function scan(root, opts = {}) {
  const started = Date.now();
  root = path.resolve(root);
  if (!fs.statSync(root).isDirectory()) throw new Error(`not a directory: ${root}`);
  const { files, skipped, truncated, javaIncomplete } = walk(root, opts);
  const scriptProject = buildScriptProject(files, !truncated && !javaIncomplete && !skipped.large);

  const raw = [];
  const fileData = new Map();
  const manifestFiles = [];
  const routes = [];
  const projFiles = [];
  const langCount = {};
  const warnings = [];
  const javaSources = [];
  let javaBytes = 0, javaComplete = !truncated && !javaIncomplete;
  for (const f of files) {
    if (detectLanguage(f.rel.replace(/\.appsec-quarantined$/, '')) !== 'java') continue;
    try {
      const buf = fs.readFileSync(f.abs);
      javaBytes += buf.length;
      if (javaBytes > 100 * 1024 * 1024 || javaSources.length >= 50000) { javaComplete = false; break; }
      if (isProbablyBinary(buf)) { javaComplete = false; continue; }
      const text = buf.toString('utf8');
      javaSources.push({ file: f.rel, raw: text, code: stripComments(text, 'java').split(/\r?\n/).join('\n') });
    } catch { javaComplete = false; }
  }
  const javaProject = buildJavaProjectIndex(javaSources, { complete: javaComplete, callArgs });

  for (const f of files) {
    let buf;
    try { buf = fs.readFileSync(f.abs); } catch { continue; }
    if (isProbablyBinary(buf)) continue;
    const text = buf.toString('utf8');
    const rawLines = text.split(/\r?\n/);
    const relLogical = f.rel.replace(/\.appsec-quarantined$/, '');
    const lang = detectLanguage(relLogical);
    if (lang) langCount[lang] = (langCount[lang] || 0) + 1;
    const code = lang ? stripComments(text, lang) : text;
    const codeLines = code.split(/\r?\n/);
    fileData.set(f.rel, { rawLines, lang });

    if (isManifest(f.rel)) manifestFiles.push({ rel: f.rel, raw: text });
    const vendored = !opts.includeVendored && isVendoredAsset(f.rel, text);

    const isLock = /(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|composer\.lock|Gemfile\.lock|poetry\.lock|go\.sum|Cargo\.lock|uv\.lock|bun\.lock)$/.test(f.rel);
    if (!isLock) {
      for (const s of scanSecrets(f.rel, text, rawLines)) {
        raw.push({ ruleId: s.ruleId, file: f.rel, line: s.line, col: s.col, severity: s.severity, confidence: s.confidence || 'high', secretRedacted: redact(s.secret), secretRaw: s.secret, detail: s.key ? `key: ${s.key}` : undefined, source: 'secrets' });
      }
    }
    raw.push(...applyConfigRules(f.rel, lang, text, rawLines, codeLines));
    if (lang && !isLock && !vendored) {
      const taint = analyzeTaint(codeLines, lang);
      raw.push(...applyCodeRules(f.rel, lang, text, codeLines, taint, javaProject, scriptProject));
      const r = extractRoutes(f.rel, lang, codeLines, text);
      routes.push(...r);
      if (['javascript', 'typescript', 'python', 'php', 'java', 'kotlin', 'go', 'ruby', 'csharp'].includes(lang)) projFiles.push({ rel: f.rel, code, lang });
    }
  }

  // Symlinks escaping the repository root
  for (const s of [...skipped.symlinks, ...(opts.repoSymlinks || [])]) if (s.escapes) raw.push({ ruleId: 'FILE-SYMLINK-001', file: s.rel, line: 1, col: 1, detail: `→ ${s.target}`, source: 'config' });

  // Supply chain
  const supply = analyzeSupplyChain(manifestFiles);
  raw.push(...supply.findings);
  if (opts.osv) {
    try { raw.push(...(await queryOsv(supply.inventory))); } catch (e) { warnings.push(`OSV query failed: ${e.message}`); }
  }

  // Surface + project rules
  raw.push(...routeFindings(routes));
  const ctx = { files: projFiles, allCode: projFiles.map((f) => f.code), routes, manifests: manifestFiles.map((m) => ({ rel: m.rel, raw: m.raw, lock: /lock|shrinkwrap|\.sum$/i.test(m.rel) })) };
  for (const rule of PROJECT_RULES) {
    try { for (const h of rule.check(ctx)) raw.push({ ruleId: rule.id, file: h.file, line: h.line || 1, col: 1, detail: h.detail, source: 'project' }); } catch { /* ignore */ }
  }

  // ---------- enrich ----------
  const lineText = (f) => { const d = fileData.get(f.file); return d ? (d.rawLines[f.line - 1] || '') : ''; };
  let findings = raw.map((f) => {
    const rule = BY_ID.get(f.ruleId) || {};
    const logicalFile = f.file.replace(/\.appsec-quarantined$/, '');
    const testCtx = isTestPath(logicalFile);
    let severity = f.severity || rule.severity || 'medium';
    let confidence = f.confidence || rule.confidence || 'medium';
    if (testCtx && f.source !== 'secrets') {
      severity = ['critical', 'high'].includes(severity) ? 'medium' : 'low';
      if (f.source !== 'supply' && f.source !== 'osv') confidence = 'low';
    } else if (testCtx && ['critical', 'high'].includes(severity)) {
      severity = 'medium'; // fixture keys/tokens are usually throwaway — still reported, not gating by default
    }
    let snippet = truncate(lineText(f).trim(), 240);
    if (f.secretRaw) snippet = snippet.split(f.secretRaw).join(f.secretRedacted);
    const owasp = rule.owasp || 'A03';
    return {
      ruleId: f.ruleId, title: f.title || rule.title || f.ruleId,
      severity, confidence, owasp, owaspName: CATEGORIES[owasp] ? CATEGORIES[owasp].name : '',
      cwe: f.cwe || rule.cwe || [], cves: f.cves, tags: rule.tags,
      file: f.file, line: f.line || 1, col: f.col || 1, snippet,
      message: f.message || rule.message || '', fix: f.fix || rule.fix || '', refs: f.refs || rule.refs || [],
      detail: f.detail, taint: f.taint, package: f.package,
      kind: f.kind || 'vulnerability',
      context: testCtx ? 'test' : 'app', source: f.source, status: 'open',
    };
  });

  // dedupe: same file+line+primary CWE → keep strongest
  const best = new Map();
  for (const f of findings) {
    const k = `${f.file}:${f.line}:${f.cwe[0]}:${f.source === 'supply' || f.source === 'osv' ? f.detail + (f.cves || []).join() : ''}`;
    const prev = best.get(k);
    if (!prev || sevRank(f.severity) * 10 + confRank(f.confidence) > sevRank(prev.severity) * 10 + confRank(prev.confidence)) best.set(k, f);
  }
  findings = [...best.values()];

  fingerprintAll(findings, lineText);

  // suppressions (target-repo inline comments are untrusted unless --trust-suppressions)
  for (const f of findings) {
    const d = fileData.get(f.file);
    if (!d) continue;
    const here = d.rawLines[f.line - 1] || '';
    const prev = d.rawLines[f.line - 2] || '';
    const m = here.match(SUPPRESS_RE) || prev.match(SUPPRESS_RE);
    if (m && (!m[1] || m[1].split(/\s*,\s*/).includes(f.ruleId))) {
      f.inlineSuppression = { reason: (m[2] || '').trim() || null };
      if (opts.trustSuppressions) f.status = 'suppressed';
    }
  }
  const ignores = loadIgnoreFile(opts.ignoreFile);
  for (const f of findings) {
    const ig = ignores.find((x) => (x.fingerprint && x.fingerprint === f.fingerprint) || (!x.fingerprint && x.ruleId === f.ruleId && x.file && f.file === x.file));
    if (!ig) continue;
    if (ig.expired) { warnings.push(`ignore for ${f.fingerprint} (${f.ruleId}) expired ${ig.expires}`); continue; }
    f.status = 'ignored'; f.ignoreReason = ig.reason || null;
  }

  // filters
  const minConf = confRank(opts.minConfidence || 'low');
  const minSev = sevRank(opts.minSeverity || 'info');
  findings = findings.filter((f) => confRank(f.confidence) >= minConf && sevRank(f.severity) >= minSev);
  if (!opts.includeTests) findings = findings.filter((f) => f.context !== 'test' || ['supply', 'osv', 'secrets'].includes(f.source));

  // baseline
  let fixedSinceBaseline;
  if (opts.baseline) {
    const prev = JSON.parse(fs.readFileSync(opts.baseline, 'utf8'));
    const prevSet = new Set((prev.findings || []).map((x) => x.fingerprint));
    for (const f of findings) f.baseline = prevSet.has(f.fingerprint) ? 'existing' : 'new';
    const cur = new Set(findings.map((f) => f.fingerprint));
    fixedSinceBaseline = (prev.findings || []).filter((x) => !cur.has(x.fingerprint)).map((x) => ({ fingerprint: x.fingerprint, ruleId: x.ruleId, file: x.file, line: x.line, title: x.title }));
  }

  findings.sort((a, b) => sevRank(b.severity) - sevRank(a.severity) || confRank(b.confidence) - confRank(a.confidence) || a.owasp.localeCompare(b.owasp) || a.file.localeCompare(b.file) || a.line - b.line);
  findings.forEach((f, i) => { f.id = `F${String(i + 1).padStart(4, '0')}`; });

  const summary = summarize(findings);
  return {
    schema: 'appsec-harness/findings@1',
    tool: { name: 'kayfabe', version: pkg.version },
    target: { root, name: opts.name || path.basename(root), ...(opts.targetMeta || {}) },
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - started,
    options: { includeTests: !!opts.includeTests, minConfidence: opts.minConfidence || 'low', trustSuppressions: !!opts.trustSuppressions, osv: !!opts.osv },
    stats: { files: files.length, languages: langCount, skipped: { large: skipped.large, binary: skipped.binaryExt, vendoredDirs: skipped.dirs, symlinks: skipped.symlinks.length }, truncated, dependencies: supply.inventory.length, routes: routes.length },
    summary,
    warnings,
    surface: routes,
    findings,
    fixedSinceBaseline,
  };
}

function summarize(findings) {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const byCategory = {};
  for (const k of Object.keys(CATEGORIES)) byCategory[k] = { name: CATEGORIES[k].name, total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    if (f.status !== 'open') continue;
    bySeverity[f.severity]++;
    byCategory[f.owasp].total++;
    byCategory[f.owasp][f.severity]++;
  }
  const open = findings.filter((f) => f.status === 'open').length;
  return { total: findings.length, open, suppressed: findings.length - open, bySeverity, byCategory };
}

module.exports = { scan, summarize, windowAt, firstArg, callArgs };
