# Independent accuracy measurements

`selftest` runs cases developed alongside the rules. Keep it as a regression check. Use independently labeled datasets to measure detection.

The OWASP adapter supports [OWASP Benchmark Java](https://github.com/OWASP-Benchmark/BenchmarkJava). OWASP publishes the intended CWE and true/false label for each servlet in `expectedresults-1.2.csv`. The adapter uses these upstream labels and runs the existing scanner without changing detection rules.

Other datasets have separate guides and scoring policies:

- [Juliet Java and NIST SARD](JULIET-SARD.md): mixed good/bad method regions and explicit SARIF labels.
- [Real CVE fixes](CVE-FIX-CORPUS.md): immutable upstream parent/fix source pairs.

Do not pool these datasets into a single accuracy claim.

## Reproduce the first baseline

Requirements: Node.js 20 or later and Git for acquiring the dataset. The commands below use only the harness; do not build the Java application or run scripts from its checkout.

```sh
node bin/appsec.js clone https://github.com/OWASP-Benchmark/BenchmarkJava \
  --ref bc5ffeb09fb18ab039806d84ca1f718c2e332c54 \
  --dest appsec-out/benchmarks/owasp-java

node bin/appsec.js benchmark owasp-java appsec-out/benchmarks/owasp-java \
  --dataset-revision bc5ffeb09fb18ab039806d84ca1f718c2e332c54 \
  --out appsec-reports/benchmarks/owasp-java
```

The example uses shell line continuations; use a single line or PowerShell backticks on Windows. The clone destination must be new or empty. Both dataset and local results directories are ignored by Git. Keep the checkout unchanged during measurement: validation, hashing, and scanning are separate reads, not an atomic snapshot.

The runner writes `benchmark.json` with every case decision and `benchmark.md` with aggregate and per-CWE results. `--json` also prints JSON to stdout. A complete measurement exits `0`, regardless of accuracy. Invalid labels, missing cases, or incomplete scans exit `2`.

Use `--expected <relative-path>` for another upstream expected-results file inside the dataset. This adapter accepts OWASP Java's four unquoted CSV fields; it is not a generic CSV importer. `--dataset-revision` accepts a full Git SHA and records it as supplied. The runner does not verify Git state: compare the recorded input hashes as well as the declared revision.

## Scoring policy

Policy ID: `owasp-java-file-cwe@1`.

- One decision per labeled servlet under `src/main/java/org/owasp/benchmark/testcode`.
- A detection requires an open finding in that exact file with the expected CWE in its CWE list. The runner uses no CWE aliases or broad category mappings.
- Multiple matching findings count as one positive prediction. A finding with the wrong CWE or outside a labeled case does not earn credit; those findings have separate counters.
- Every labeled case is scored, including categories the scanner does not support. No confidence or severity tuning is used: test paths are included, confidence starts at `low`, and severity starts at `info`.
- Inline suppression comments are not trusted. OSV querying is disabled so network responses cannot change the measurement.
- Missing, linked, binary, oversized, or otherwise scanner-skipped case files invalidate the run. File-count truncation also invalidates it.
- Output must be outside the dataset. The reports contain identifiers, locations, rule IDs, and measurements, without source snippets.

TPR (recall) = TP / (TP + FN). FPR = FP / (FP + TN). Precision = TP / (TP + FP). Zero denominators produce `null` in JSON and `n/a` in Markdown. The overall row pools cases across CWEs (micro averaging); it is not an average of per-CWE percentages.

For the upstream rationale, see [OWASP's scoring documentation](https://owasp.org/www-project-benchmark/). This adapter's strict matching and aggregate reports are described above; no official OWASP scorecard generator was used.

## First measurement

Measured October 19, 2026 (America/New_York), with Node 24.16.0 on Windows. Upstream commit: `bc5ffeb09fb18ab039806d84ca1f718c2e332c54`. Harness implementation commit: `995b91552f241adc471cd8a588fc68753d87e56d`; the baseline also records the exact harness source bytes by hash.

| CWE | Cases | TP | FP | TN | FN | Recall | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|
| 22 — Path traversal | 268 | 2 | 8 | 127 | 131 | 1.50% | 5.93% |
| 78 — OS command injection | 251 | 79 | 72 | 53 | 47 | 62.70% | 57.60% |
| 79 — Cross-site scripting | 455 | 160 | 105 | 104 | 86 | 65.04% | 50.24% |
| 89 — SQL injection | 504 | 205 | 129 | 103 | 67 | 75.37% | 55.60% |
| 90 — LDAP injection | 59 | 0 | 0 | 32 | 27 | 0.00% | 0.00% |
| 327 — Broken/risky cryptography | 246 | 0 | 0 | 116 | 130 | 0.00% | 0.00% |
| 328 — Weak hash | 236 | 89 | 0 | 107 | 40 | 68.99% | 0.00% |
| 330 — Insufficient randomness | 493 | 0 | 0 | 275 | 218 | 0.00% | 0.00% |
| 501 — Trust boundary violation | 126 | 0 | 0 | 43 | 83 | 0.00% | 0.00% |
| 614 — Sensitive cookie without Secure | 67 | 36 | 0 | 31 | 0 | 100.00% | 0.00% |
| 643 — XPath injection | 35 | 0 | 0 | 20 | 15 | 0.00% | 0.00% |
| Total | 2,740 | 571 | 314 | 1,011 | 844 | 40.35% | 23.70% |

Overall precision: **64.52%**. There were also 878 findings with mismatched CWEs in labeled files and 107 findings outside the labeled files. Those are not automatically 985 additional false positives; this dataset does not supply ground truth for those predictions.

The checked-in [aggregate JSON](benchmarks/owasp-java-1.2-baseline.json) records the hashes, runtime, scan settings, per-CWE precision, and counts. Full per-case reports are generated locally by the commands above.

The low scores identify work to investigate. Zero recall may reflect detection gaps, CWE classification, or both. High false-positive rates in command injection, XSS, and SQL injection deserve investigation before expanding those rules. This measurement alone does not establish which implementation change would fix them.

## Limits

OWASP Benchmark is independently authored but synthetic. This run does not measure production application accuracy, cross-file flow coverage, or agent triage. The evaluator's unit fixtures check arithmetic and input handling; they are not independent accuracy data.

The Juliet/SARD adapters and CVE-fix corpus use their own policies, described in the linked guides above. The [roadmap](ROADMAP.md) tracks remaining dataset expansion and detection work.
