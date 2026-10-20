'use strict';
const fs = require('fs');
const path = require('path');
const { toSarif } = require('./sarif');
const { toJUnit } = require('./junit');
const { toMarkdown } = require('./markdown');
const { toHtml } = require('./html');
const { buildTriageRequest } = require('../triage');

const ALL_FORMATS = ['json', 'sarif', 'junit', 'md', 'html', 'triage'];

function writeReports(result, outDir, { formats = ALL_FORMATS, gate, failOn = 'high', prefix = '' } = {}) {
  fs.mkdirSync(outDir, { recursive: true });
  const written = {};
  const w = (name, content) => { const p = path.join(outDir, prefix + name); fs.writeFileSync(p, content); written[name] = p; };
  const want = new Set(formats.includes('all') ? ALL_FORMATS : formats);
  if (want.has('json')) w('findings.json', JSON.stringify({ ...result, gate }, null, 2));
  if (want.has('sarif')) w('results.sarif', JSON.stringify(toSarif(result), null, 2));
  if (want.has('junit')) w('junit.xml', toJUnit(result, { failOn }));
  if (want.has('md')) w('report.md', toMarkdown(result, { gate }));
  if (want.has('html')) w('report.html', toHtml(result, { gate }));
  if (want.has('triage') && !result.triage) w('triage-request.json', JSON.stringify(buildTriageRequest(result), null, 2));
  return written;
}

module.exports = { writeReports, ALL_FORMATS };
