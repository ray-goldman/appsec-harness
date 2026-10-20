# Independent accuracy: first implementation milestone

The user authorized recording the complete roadmap and starting priority 1. This milestone adds OWASP Benchmark Java scoring to the existing CLI and scanner. It does not tune detection rules to the benchmark.

## Design

`appsec benchmark owasp-java <directory>` reads the upstream expected-results CSV and scans the checkout statically. No application builds, dependency installation, network requests, or target code execution occur during benchmarking. Use the existing hardened clone command to acquire data separately.

Each labeled Java servlet is one decision. A positive prediction requires an open finding in that exact test-case path whose CWE list contains the expected CWE. Duplicate findings count once. Other findings are counted separately, with reasons, and do not earn credit. All labeled cases remain in the denominator.

The report contains the confusion matrix and rates per CWE and overall. Undefined rates are null, never 100%. Missing, unreadable, linked, or scanner-skipped case files and truncated scans abort the evaluation. Metadata records the expected-results hash, a content hash of scanner inputs, declared dataset revision, harness version and code hash, scan options, and scoring-policy version. A declared Git revision is not a substitute for content hashes.

Outputs are JSON and Markdown. A complete measurement exits zero even when detection is poor; malformed inputs and incomplete measurements exit two. Output directories inside the dataset are refused.

## Implementation sequence

1. Add tests with hand-calculated confusion matrices: duplicate detections, wrong CWE/path, negative cases, empty denominators, and malformed or duplicate labels.
2. Implement `src/benchmark.js`: strict OWASP CSV import, complete-case validation, static scan, scoring, provenance, and reports.
3. Add the CLI command and help text. Test it end to end with a small temporary Java dataset, including missing/oversized/linked inputs and output confinement.
4. Make the existing directory-link regression test runnable on Windows using a junction, preserving its link-confinement assertions.
5. Run the full unit suite and existing corpus regression suite. Run the new adapter on the pinned external OWASP checkout and save an aggregate baseline.
6. Document how to reproduce the measurement and its limitations. Update README accuracy wording and link the roadmap.

## Acceptance

- Per-CWE counts reconcile to every upstream case, with no exclusion of unsupported categories.
- JSON and Markdown agree; no source snippets or credential values are published in the baseline.
- The report identifies the exact inputs and configuration.
- Tests validate the evaluator's arithmetic and failure behavior. The OWASP run measures scanner accuracy; tests written here do not.
- Juliet/SARD and CVE-fix work remain visibly pending in the roadmap.
