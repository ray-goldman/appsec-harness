'use strict';
const path = require('node:path');
const { stripComments, maskStrings } = require('./languages');
const { checkedFile } = require('./benchmark');
const { datasetRoot, inventory, readBounded, sha256, runLabeled, regionIndex, markdown } = require('./benchmark-labeled');
const JULIET_13_MANIFEST_SHA256 = 'e0227dee176a75d56aee13482bea309dc78fdfc707762bb7ce42336e7ef6045b';

// Deliberately restricted grammar for the official Juliet manifest, not a general XML parser.
function parseManifest(text, allowJuliet13Defects = false) {
  if (text.length > 32 * 1024 * 1024 || /<!|&/.test(text)) throw new Error('unsupported XML declaration/entity or oversized Juliet manifest');
  text = text.replace(/^\uFEFF?<\?xml version="1\.0" encoding="utf-8"\?>\s*/i, '');
  const stack = [], cases = [];
  let testcase, file, cursor = 0, redundantTestcaseClosings = 0;
  const tag = /<([^<>]{1,4096})>/g;
  for (let match; (match = tag.exec(text));) {
    if (text.slice(cursor, match.index).trim()) throw new Error('unexpected Juliet manifest text');
    cursor = tag.lastIndex;
    const token = match[1], close = token.startsWith('/'), empty = token.endsWith('/');
    const body = token.slice(close ? 1 : 0, empty ? -1 : undefined).trim();
    const name = body.match(/^[a-z]+/)?.[0];
    if (!name || !['container', 'testcase', 'file', 'flaw'].includes(name)) throw new Error('unsupported Juliet XML element');
    const attrs = {};
    let rest = body.slice(name.length);
    while (rest.trim()) {
      const attr = rest.match(/^\s+([a-z]+)="([^"<]{0,2048})"/);
      if (!attr || Object.hasOwn(attrs, attr[1])) throw new Error('invalid Juliet XML attribute');
      attrs[attr[1]] = attr[2]; rest = rest.slice(attr[0].length);
    }
    if (close) {
      if (allowJuliet13Defects && name === 'testcase' && stack.at(-1) === 'container' && !Object.keys(attrs).length) {
        redundantTestcaseClosings++; continue;
      }
      if (Object.keys(attrs).length || stack.pop() !== name) throw new Error('unbalanced Juliet XML');
      continue;
    }
    const parent = stack.at(-1);
    if (name === 'container') {
      if (parent || cases.length || Object.keys(attrs).length || empty) throw new Error('invalid Juliet container');
    } else if (name === 'testcase') {
      if (parent !== 'container' || Object.keys(attrs).length || empty) throw new Error('invalid Juliet testcase');
      testcase = { files: [] }; cases.push(testcase);
    } else if (name === 'file') {
      if (parent !== 'testcase' || Object.keys(attrs).join() !== 'path' || !/^[\w.-]+$/.test(attrs.path)) throw new Error('invalid Juliet file');
      file = { basename: attrs.path, flaws: [] }; testcase.files.push(file);
    } else {
      if (parent !== 'file' || !empty || Object.keys(attrs).sort().join() !== 'line,name' ||
          !/^[1-9]\d{0,6}$/.test(attrs.line) || !/^CWE-0*[1-9]\d{0,4}: /.test(attrs.name)) throw new Error('invalid Juliet flaw');
      file.flaws.push({ line: Number(attrs.line), cwe: Number(attrs.name.match(/^CWE-(\d+)/)[1]) });
    }
    if (!empty) stack.push(name);
  }
  if (stack.length || text.slice(cursor).trim() || !cases.length) throw new Error('incomplete Juliet manifest');
  cases.redundantTestcaseClosings = redundantTestcaseClosings;
  return cases;
}

function methodRegions(raw, file) {
  const text = maskStrings(stripComments(raw, 'java'), 'java');
  const lineStarts = [0];
  for (let i = 0; i < text.length; i++) if (text[i] === '\n') lineStarts.push(i + 1);
  const lineAt = (offset) => {
    let lo = 0, hi = lineStarts.length;
    while (lo + 1 < hi) { const mid = (lo + hi) >>> 1; if (lineStarts[mid] <= offset) lo = mid; else hi = mid; }
    return lo + 1;
  };
  const endings = new Map(), braces = [];
  for (let i = 0; i < text.length; i++) {
    if (text[i] === '{') braces.push(i);
    else if (text[i] === '}') {
      if (!braces.length) throw new Error(`unbalanced Java source: ${file}`);
      endings.set(braces.pop(), i);
    }
  }
  if (braces.length) throw new Error(`unbalanced Java source: ${file}`);
  const re = /^[ \t]*(?:(?:public|protected|private|static|final|synchronized|strictfp)\s+)*(?:[\w$]+(?:<[^;{}]{0,300}>)?(?:\[\])?\s+)?([\w$]+)\s*\([^;{}]{0,2000}\)\s*(?:throws[^;{}]{0,500})?\s*\{/gm;
  const regions = [];
  for (let match; (match = re.exec(text));) {
    if (['if', 'while', 'for', 'switch', 'catch', 'synchronized'].includes(match[1])) continue;
    const open = re.lastIndex - 1, end = endings.get(open);
    if (end === undefined) throw new Error(`unclosed Java method: ${file}`);
    regions.push({ file, name: match[1], startLine: lineAt(match.index), endLine: lineAt(end) });
  }
  return regions;
}

function loadJuliet(root, files, expected = 'manifest.xml') {
  const manifestBytes = readBounded(root, expected, 32 * 1024 * 1024);
  const official13 = sha256(manifestBytes) === JULIET_13_MANIFEST_SHA256;
  const entries = parseManifest(manifestBytes.toString('utf8'), official13);
  const byBasename = new Map();
  for (const file of files.filter((x) => x.startsWith('src/testcases/') || x.startsWith('src/testcasesupport/'))) {
    const basename = path.posix.basename(file);
    if (!byBasename.has(basename)) byBasename.set(basename, []);
    byBasename.get(basename).push(file);
  }
  const labels = [], seen = new Set();
  const metadata = { manifestTestcases: entries.length, manifestFlaws: 0, exactLineFallbacks: 0, casesWithoutGoodRegions: 0, nonJavaFiles: 0,
    manifestFileSha256: sha256(manifestBytes), officialJuliet13Manifest: official13,
    redundantTestcaseClosings: entries.redundantTestcaseClosings, casesWithoutManifestFlaws: 0, overriddenFlawAnchors: [] };
  for (const [index, testcase] of entries.entries()) {
    const caseFiles = [], cwes = new Set();
    for (const entry of testcase.files) {
      const found = byBasename.get(entry.basename);
      if (!found || found.length !== 1) throw new Error(`missing or ambiguous Juliet manifest file: ${entry.basename}`);
      const file = found[0];
      checkedFile(root, file);
      for (const flaw of entry.flaws) { cwes.add(flaw.cwe); metadata.manifestFlaws++; }
      if (!file.endsWith('.java')) {
        metadata.nonJavaFiles++;
        if (entry.flaws.length) throw new Error(`non-Java labeled flaw unsupported: ${file}`);
        continue;
      }
      const raw = readBounded(root, file).toString('utf8'), lines = raw.split('\n').length;
      const methods = methodRegions(raw, file);
      const classPolarity = entry.basename.match(/_(good\w*|bad)\.java$/)?.[1];
      caseFiles.push({ ...entry, file, methods, lines, classPolarity });
    }
    if (!cwes.size) {
      metadata.casesWithoutManifestFlaws++;
      for (const item of caseFiles) {
        const match = item.basename.match(/^CWE(\d+)_/);
        if (!match || !Number(match[1])) throw new Error(`missing Juliet CWE in testcase ${index + 1}`);
        cwes.add(Number(match[1]));
      }
      if (cwes.size !== 1) throw new Error(`ambiguous Juliet filename CWE in testcase ${index + 1}`);
    }
    for (const cwe of cwes) {
      const bad = [], good = [], anchors = [];
      for (const item of caseFiles) {
        const { file, methods, classPolarity } = item;
        if (classPolarity) {
          (classPolarity.startsWith('good') ? good : bad).push({ file, startLine: 1, endLine: item.lines, name: classPolarity, basis: 'Juliet class-name convention' });
        } else {
          for (const region of methods) {
            if (/^good(?:[A-Z0-9_]|$)/.test(region.name)) good.push({ ...region, basis: 'Juliet good-method convention' });
            if (/^bad(?:[A-Z0-9_]|$)/.test(region.name)) bad.push({ ...region, basis: 'Juliet bad-method convention' });
          }
        }
        for (const flaw of item.flaws.filter((x) => x.cwe === cwe)) {
          if (flaw.line > item.lines) throw new Error(`Juliet flaw outside source: ${file}:${flaw.line}`);
          anchors.push({ file, line: flaw.line });
          if (bad.some((r) => r.file === file && r.startLine <= flaw.line && r.endLine >= flaw.line)) continue;
          const enclosing = methods.filter((r) => r.startLine <= flaw.line && r.endLine >= flaw.line).sort((a, b) => (a.endLine - a.startLine) - (b.endLine - b.startLine))[0];
          if (good.some((r) => r.file === file && r.startLine <= flaw.line && r.endLine >= flaw.line)) {
            if (!official13) throw new Error(`conflicting Juliet good/flaw labels: ${file}:${flaw.line}`);
            metadata.overriddenFlawAnchors.push({ file, line: flaw.line, cwe, reason: 'official manifest flaw conflicts with explicit Juliet good naming; suite polarity takes precedence' });
            continue;
          }
          if (enclosing) bad.push({ ...enclosing, basis: 'manifest flaw in method' });
          else { bad.push({ file, startLine: flaw.line, endLine: flaw.line, basis: 'manifest exact flaw line' }); metadata.exactLineFallbacks++; }
        }
      }
      const id = `testcase-${index + 1}:CWE-${cwe}`;
      const identity = caseFiles.map((x) => x.file).sort().join('|') + `:${cwe}`;
      if (seen.has(identity)) throw new Error(`duplicate Juliet testcase: ${id}`);
      seen.add(identity);
      if (!bad.length) throw new Error(`no explicit bad regions in Juliet testcase ${index + 1}`);
      labels.push({ id: `${id}:bad`, cwe, vulnerable: true, regions: bad, manifestFlaws: anchors });
      if (good.length) labels.push({ id: `${id}:good`, cwe, vulnerable: false, regions: good });
      else metadata.casesWithoutGoodRegions++;
    }
  }
  return { labels, metadata };
}

async function runJulietBenchmark(directory, opts = {}) {
  const root = datasetRoot(directory), files = inventory(root), expected = opts.expected || 'manifest.xml';
  const { labels, metadata } = loadJuliet(root, files, expected);
  return runLabeled(root, opts, {
    name: 'Juliet Java', source: 'https://samate.nist.gov/SARD/test-suites/111', defaultOut: 'appsec-reports/benchmarks/juliet-java',
    version: metadata.officialJuliet13Manifest ? '1.3' : null,
    labels, metadata, inputFiles: files, manifestFiles: [expected], regionsByFile: regionIndex(labels),
    policy: {
      id: 'juliet-java-testcase-cwe-polarity-regions@1',
      unit: 'one manifest testcase × CWE × bad/good polarity; methods and helper classes are aggregated',
      match: 'open finding with exact CWE and path, with its start line inside a labeled method/class region (or exact manifest flaw line when no method encloses it)',
      limitations: [
        'Manifest flaw labels anchor bad regions. Good regions require explicit Juliet good method/class naming; missing good regions never create a negative.',
        'The official 1.3 manifest contains redundant closing testcase tags and cases without flaw entries. Redundant closings are counted and ignored; missing-flaw cases use the explicit CWE filename plus bad/good naming convention and remain in the denominator.',
        'For the exact official 1.3 manifest hash only, an anchor conflicting with an explicitly good region is recorded and the suite good/bad convention takes precedence. This is corrected-label scoring, not pristine manifest scoring.',
        'All good variants, wrappers, and helpers in a testcase form one negative unit. One matching detection anywhere predicts the aggregate positive; this is not per-method or per-flaw accuracy.',
        'Neutral methods enclosing manifest flaws are bad regions. Other neutral helper methods, main/support code, and unlabeled source regions are unscored.',
        'Separate good/bad helper classes use their complete original file regions. No target source is rewritten and scanner taint analysis still sees coexisting good/bad methods.',
        'No call-graph reachability or cross-file taint is added by the evaluator; an intra-method or helper-class detection can satisfy its testcase unit.',
      ],
    },
  });
}

module.exports = { runJulietBenchmark, toMarkdown: markdown, parseManifest, methodRegions, loadJuliet };
