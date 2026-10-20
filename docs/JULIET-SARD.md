# Juliet Java and NIST SARD measurements

These adapters evaluate independently labeled synthetic source without building or executing it. They use the harness scanner unchanged: test paths included, all severities, confidence low and above, inline suppressions disabled, and OSV disabled. Unsupported CWEs remain in the denominator.

The download URLs, official suite pages, archive SHA-256 values, and license notes are recorded in [`benchmarks/nist-datasets.json`](../benchmarks/nist-datasets.json). Source archives and extracted target code stay in ignored local directories.

## Reproduce

Use Node 20 or newer and the zero-dependency harness checkout. Download the two archives from the URLs in the metadata file and check each archive's SHA-256 **before extracting**. For example, in PowerShell from the harness directory:

```powershell
$datasets = (Get-Content benchmarks/nist-datasets.json -Raw | ConvertFrom-Json).datasets
New-Item -ItemType Directory -Force appsec-out/benchmarks/downloads
foreach ($dataset in $datasets) {
  $archive = Join-Path 'appsec-out/benchmarks/downloads' ($dataset.id + '.zip')
  Invoke-WebRequest -Uri $dataset.archiveUrl -OutFile $archive
  if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $dataset.archiveSha256) {
    throw "Archive hash mismatch: $($dataset.id)"
  }
}
```

Extract the Juliet archive into `appsec-out/benchmarks/juliet-java-1.3`, preserving its `Java` directory. Extract suite 115 into `appsec-out/benchmarks/sard-115`, preserving the 20 case directories and their SARIF manifests. Use an extractor that rejects path traversal and symbolic links. Juliet includes long filenames: on Windows use a short extraction root or an extractor that supports extended-length paths. A partial extraction fails the runner's missing-input checks.

```console
node bin/appsec.js benchmark juliet-java appsec-out/benchmarks/juliet-java-1.3/Java --out appsec-reports/benchmarks/juliet-java
node bin/appsec.js benchmark sard appsec-out/benchmarks/sard-115 --out appsec-reports/benchmarks/sard-115
```

Each command writes `benchmark.json` and `benchmark.md` outside the dataset. JSON includes individual labels, original source regions, matched findings, per-CWE and aggregate counts, scanner settings, Node/platform, and hashes of the input files, label files, and harness source. Source and input hashes are checked again after scanning; changing either during a scan fails the run. `--expected` selects one relative manifest path; without it Juliet uses `manifest.xml` and SARD discovers all files named `manifest.sarif`. Paths must stay within the dataset. `--dataset-revision` accepts a full Git commit SHA as a declaration and does not verify it; archive hashes in the source metadata are the download provenance.

## Juliet scoring

A labeled unit is **one manifest testcase × CWE × polarity**. All bad methods and helper classes in a testcase form one positive unit. All good variants, wrappers, and helper classes form one negative unit. Thus calling `goodG2B()` from `good()` does not create two negative cases.

An open scanner finding predicts a unit positive when its CWE matches exactly, its source path matches, and its start line falls in one of the unit's regions. Duplicate findings do not increase the unit's count.

Bad regions come from explicit `bad*` methods or `_bad.java` helper classes, together with the methods containing manifest flaw lines. Good regions require explicit `good*` methods or `_good*.java` classes. Named helper classes use the full original file as their region. A flaw outside any recognized method remains a positive exact-line region. The evaluator does not rewrite source, mask good code from the scanner, add taint propagation, or add call-graph reachability.

Neutral helpers without a manifest flaw, support code, `main` methods in ordinary mixed files, and other unlabeled regions are unscored. A testcase without an explicit good region has no negative unit. The report records such cases. This grouping measures whether any corresponding detection occurred in a flow's regions; it is not per-method, per-flaw, or executable-path accuracy. Scanner analysis still sees good and bad methods together in the original file.

### Published manifest defects

The official Juliet 1.3 `manifest.xml` has SHA-256:

```text
e0227dee176a75d56aee13482bea309dc78fdfc707762bb7ce42336e7ef6045b
```

That manifest contains redundant `</testcase>` tags, missing flaw entries, and flaw entries attached to explicitly good code. For example, `CWE491_Object_Hijack__basic_01_good1.java:21` declares the fixed, final clone method, but the manifest marks it as a flaw.

The adapter applies a narrow compatibility policy:

- Redundant closing testcase tags are counted and ignored only for this exact manifest hash. Other unbalanced manifests fail.
- When a testcase has no flaw entries, its explicit `CWE###_` source filename supplies the CWE, and explicit good/bad names supply polarity. These cases remain in the denominator.
- For this exact official manifest hash, an anchor inside an explicitly good region is recorded in `dataset.overriddenFlawAnchors` and suite naming takes precedence. Both convention-labeled bad and good units remain. Other manifests with such conflicts fail.

The Markdown report shows compatibility counts. JSON records each overridden file, line, CWE, and reason, plus the count of missing-flaw cases and redundant closings. The dataset version is `1.3` only when this manifest hash matches. This is explicitly **corrected-label scoring**, not pristine manifest scoring.

The XML reader supports only the small upstream container/testcase/file/flaw grammar. It bounds input and attributes and rejects DTDs, entities, and other markup. Basenames must resolve uniquely among original testcase and support files.

## SARD scoring

A labeled unit is **one explicit SARIF result location × CWE × polarity**. Manifests must use SARIF 2.1.0 and have an explicit `run.properties.state` of `bad`, `good`, or `mixed`.

For a bad or good run, explicit result locations inherit that polarity. Mixed runs must supply `result.kind: fail/pass` or `result.properties.state: bad/good`. Conflicting states fail. A good run with no explicit labeled results does not produce invented negative locations; it fails as unsupported metadata.

A detection must have the exact CWE, source file, and labeled line. If the upstream result explicitly supplies an inclusive end line, that range is used. No line tolerance, CWE aliases, or file-level fallback is applied. A valid nearby source/sink detection can therefore be a miss under this policy.

Artifact URIs are resolved relative to their manifest. URI/index disagreement, undeclared artifacts, duplicate/conflicting labels, URI base IDs, remote URLs, absolute paths, traversal, symbolic links, missing files, oversized sources, and scanner truncation fail the measurement. Supplied artifact byte lengths and SHA-256 values are enforced. JSON preserves upstream hashes and computed SHA-256 values; any other supplied hash algorithms are retained but not verified.

Suite 115 contains 20 bad CWE-79 PHP cases and **no negative cases**. Its FPR is therefore undefined (`null` in JSON, `n/a` in Markdown). A precision value of 100% on this all-positive suite does not establish false-positive performance.

## Interpretation

The completed Juliet run covers all 28,881 upstream testcases: 57,649 bad/good
units across 112 CWEs, with 8.34% recall, 8.14% FPR, and 50.72% precision.
The completed SARD suite 115 run detected 10 of 20 bad locations: 50% recall,
with no negative denominator. The checked-in [Juliet aggregate](benchmarks/juliet-java-1.3-baseline.json)
and [SARD case-level baseline](benchmarks/sard-115-baseline.json) retain the
counts and provenance. See [the gap report](DETECTION-GAPS.md) for unresolved
coverage and false-positive problems.

Recall is `TP / (TP + FN)`, FPR is `FP / (FP + TN)`, and precision is `TP / (TP + FP)`. Undefined rates are `null`. All declared units and CWEs participate, including unsupported weaknesses and misses. Finding counts outside labeled files/regions and findings with other CWEs are reported separately.

Results characterize these synthetic datasets and these matching policies. They do not establish production application accuracy, cross-file recall, human triage accuracy, or certification by NIST.
