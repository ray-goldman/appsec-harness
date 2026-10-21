'use strict';

const crypto = require('node:crypto');
const { datasetRoot, inventory, regionIndex, runLabeled, sha256 } = require('./benchmark-labeled');
const { loadJulietCSharpUnits, validateJulietUnitManifest } = require('./dotnet-juliet-units');

const SOURCE = 'https://samate.nist.gov/SARD/test-suites/110';

function prepareDotnetJulietBenchmark(directory, manifest) {
  if (!validateJulietUnitManifest(manifest) || !manifest.sourceArchiveSha256) throw new Error('invalid Juliet C# source and unit manifest');
  const root = datasetRoot(directory), inputFiles = inventory(root);
  const loaded = loadJulietCSharpUnits(root, inputFiles, manifest);
  const multiFileUnits = loaded.units.filter(unit => unit.labelIds.length > 1).length;
  return {
    name: 'Juliet C# 1.3',
    source: SOURCE,
    version: '1.3',
    labels: loaded.labels,
    inputFiles,
    manifestFiles: [],
    regionsByFile: regionIndex(loaded.labels),
    metadata: {
      expectedSha256: loaded.labelsSha256,
      labelsSha256: loaded.labelsSha256,
      sourceArchiveSha256: manifest.sourceArchiveSha256,
      unitManifestSha256: sha256(JSON.stringify(manifest)),
      units: loaded.units.length,
      crossFileUnits: multiFileUnits,
      sourceLabelRegions: loaded.sourceLabelCount,
      unlabelledSupportFiles: loaded.supportFilesWithoutPolarity.length,
    },
    policy: {
      id: 'juliet-csharp-testcase-cwe-polarity-regions@1',
      unit: `one file × CWE × polarity, except declared multi-file suffix variants (${manifest.crossFileVariants.map(item => item.id).join(', ')}), which count once per family, variant, CWE, and polarity (including 81 bad/good split)`,
      match: 'open finding with exact CWE and path, with its start line inside a labeled Bad/Good method or explicitly named bad/good class region in any file in the unit',
      limitations: [
        'Ground-truth regions use Juliet C# method names beginning Bad/Good and explicitly named bad/good class files; 81 base/helper files are included in source hashing and scanning but are not polarity labels.',
        'The public NIST archive does not include a standalone manifest; the archive hash and generated label hash are recorded, and file names plus labeled source regions determine the units.',
        'This benchmark is synthetic third-party test code, not independent ASP.NET application evidence or a measure of production false-positive rates.',
      ],
    },
  };
}

async function runDotnetJulietBenchmark(directory, opts = {}) {
  const manifest = opts.unitManifest || require('../docs/benchmarks/dotnet-juliet-cross-file-units.json');
  const definition = prepareDotnetJulietBenchmark(directory, manifest);
  return runLabeled(datasetRoot(directory), opts, {
    ...definition,
    defaultOut: 'appsec-reports/benchmarks/dotnet-juliet-csharp',
  });
}

module.exports = { prepareDotnetJulietBenchmark, runDotnetJulietBenchmark };
