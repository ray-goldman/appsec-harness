'use strict';
const { parseCSharp } = require('./parser');

function analyzeCSharpFile(file, source) {
  if (typeof file !== 'string' || typeof source !== 'string') throw new TypeError('file and source are required');
  if (!/\.cs$/i.test(file) || /\.(?:cshtml|razor)$/i.test(file)) {
    return { ast: null, complete: false, fallback: true, findingsContext: null, coverage: { eligible: false, discoveredMethods: 0, parsedMethods: 0 } };
  }
  const ast = parseCSharp(source);
  return { ast, complete: ast.complete, fallback: !ast.complete, findingsContext: ast.complete ? ast : null,
    coverage: { eligible: true, discoveredMethods: ast.coverage.discoveredMethods, parsedMethods: ast.coverage.parsedMethods } };
}

module.exports = { analyzeCSharpFile };
