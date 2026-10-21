'use strict';

const path = require('node:path');
const { runDotnetJulietBenchmark } = require('../src/dotnet-juliet-benchmark');

async function main() {
  const dataset = path.resolve(process.argv[2] || 'appsec-out/benchmarks/juliet-csharp-1.3');
  const output = process.argv[3] ? path.resolve(process.argv[3]) : undefined;
  const dotnetProjectAnalysis = process.argv.includes('--dotnet-project-analysis');
  const result = await runDotnetJulietBenchmark(dataset, { out: output, dotnetProjectAnalysis });
  process.stdout.write(`${JSON.stringify({ dataset: result.dataset, totals: result.totals, parserCoverage: result.scan.stats.csharpParser, dotnetProject: result.scan.stats.dotnetProject }, null, 2)}\n`);
}

main().catch(error => {
  process.stderr.write(`Juliet benchmark failed: ${error.message}\n`);
  process.exitCode = 1;
});
