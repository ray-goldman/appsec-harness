'use strict';
// Diagnostic only: reads supplied source as data, never imports or executes it.
const fs = require('node:fs');
const crypto = require('node:crypto');
const { stripComments, analyzeTaint } = require('../src/languages');
const { goFunctionTaint } = require('../src/go-scopes');
const { toolHash } = require('../src/benchmark');
const [input, output] = process.argv.slice(2);
if (!input || !output) throw new Error('Usage: node scripts/explain-go-basename.js <go-api/main.go> <output.json>');
const raw = fs.readFileSync(input, 'utf8');
if (raw.length > 100000) throw new Error('Diagnostic source budget exceeded');
const code = stripComments(raw, 'go').replace(/\r\n/g, '\n');
// This diagnostic deliberately targets the supplied fixture's exact handler.
const match = code.match(/^func fileSafeHandler\(w http.ResponseWriter, r \*http.Request\) \{\n([^{}]*?)\n\}/m);
if (!match) throw new Error('Supplied handler shape changed; review before interpreting results');
const body = match[1], expression = 'filepath.Join(root, name)';
const sinkOffset = code.indexOf('os.ReadFile(filepath.Join(root, name))', match.index);
if (sinkOffset < match.index || sinkOffset > match.index + match[0].length) throw new Error('Expected sink missing');
const line = code.slice(0, sinkOffset).split('\n').length - 1;
const file = analyzeTaint(code.split('\n'), 'go');
const local = analyzeTaint(body.split('\n'), 'go');
const strict = analyzeTaint(body.split('\n'), 'go', { genericSanitizers: false });
const result = {
  schema: 'kayfabe/go-basename-diagnostic@1',
  sourceSha256: toolHash(), inputSha256: crypto.createHash('sha256').update(raw).digest('hex'),
  file: 'go-api/main.go', sinkLine: line + 1,
  fileHeuristic: { nameTainted: file.tainted.has('name'), sinkEvidence: file.lineTainted(expression) },
  functionHeuristic: { nameTainted: local.tainted.has('name'), sinkEvidence: local.lineTainted(expression) },
  functionWithoutGenericSanitizers: { nameTainted: strict.tainted.has('name'), sinkEvidence: strict.lineTainted(expression) },
  currentSinkEvidence: goFunctionTaint(code, raw, file)(line, 'GO-PATH-001').lineTainted(expression),
  conclusion: 'Function isolation alone drops the warning through a generic basename sanitizer heuristic. Current analysis retains request-derived basename taint; the handler has no IsLocal rejection.',
  limits: 'Static taint diagnostic only; no target execution, filesystem assumptions, exploitability claim or label change. Function-local diagnostic source lines are relative to the extracted body.',
};
fs.writeFileSync(output, JSON.stringify(result, null, 2) + '\n');
console.log(JSON.stringify(result, null, 2));
