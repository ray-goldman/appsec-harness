# Constant-member SQL precision

## What the supplied set measures

The supplied bundles contain 32 safe labels: 20 C# and 12 native C. Their provenance records prior exposure to Kayfabe documentation and earlier findings, plus same-session authorship and reviews. These are development cases, not an independent or blind evaluation. There are no vulnerable cases, so this set measures no recall or true-positive performance.

Both archive checksums and all 66 supplied file-manifest entries were verified. All 67 extracted files, including the manifests, remain unchanged. Application source was scanned separately from the key and verification material. No application builds, tests or dependency installs ran in this evaluation; execution claims in the supplied logs remain the author's claims.

## Results on the new set

Default and experimental project profiles produced the same results and are reported separately in the retained score files.

| Measurement, each profile | Main baseline | Final implementation |
|---|---:|---:|
| Raw C# SQL candidates | 2 | 1 |
| Labeled safe cases with a matching FP | 1 | 1 |
| Labeled C# true negatives | 19 | 19 |
| Case false-positive rate | 5% | 5% |
| Additional unmatched warning, adjudicated FP | 1 | 0 |
| Native C cases unsupported | 12 | 12 |
| Native C true negatives credited | 0 | 0 |

The removed service warning interpolates a literal `const string` from another source file. The request value is a bound SQL parameter. The remaining controller warning uses the same constant pattern, but automatic suppression cannot yet establish inherited framework member binding. It remains a known false positive; it is not relabeled or removed from the denominator.

The supplied policy permits several rule events per case while counting TNs by case. The local scoring addendum retains that event rate and also reports a case rate using unique affected safe cases. Both happen to be 5% here. Exact paths, ranges expanded by three lines, decoy locations, nearest-range selection and unresolved ties follow the supplied policy. Findings for a different CWE are adjudicated separately. The service warning lies outside the labeled ranges and is not counted as an extra case.

## Supported proof

The new filter applies only to a complete `.CommandText = <one interpolated string>;` expression. Every hole must resolve to a unique visible source `Type.Member` declared as a public/internal `const string`, initialized entirely from string literals. Ordinary and raw strings are supported; calls, formatting, alignment, escaped braces, dynamic suffixes and unknown expressions retain the finding.

The proof assumes a standalone standard SDK project with default compile items and the complete compilation source in the scanned snapshot. It accepts one narrowly parsed project file, with ordinary scalar project properties and an optional Microsoft.Data.Sqlite reference with a numeric version spelling. Conditions, custom compile items, project references, imports, targets and other package/build forms decline. External build customization or compiler inputs outside the snapshot are outside this model; this is not compiler validation.

Consumer files must use global or file-scoped namespaces. Only ordinary class owners are supported; structs, records and default interface methods retain warnings. Consumer classes may list only unique visible source interfaces in a flat base list. Class inheritance, including Controller/ControllerBase, is unsupported. Generic, nested, partial and file-local type bindings, aliases/global imports, directives, excluded build/vendor/hidden source and unrecognized uses of type names retain warnings. Reserved/contextual keyword receivers are unsupported, including implicit `value` and `field` bindings.

Bounds remain 1,000 C# files, 8 MiB aggregate source, 100,000 characters/20,000 tokens per source, 20,000 characters per project and 64 initializer tokens. Existing taint and constant-proof paths retain their scope.

## Tests and reviews

The initial two public positive-proof regressions failed before implementation; the dynamic neighbor remained a finding. The final exact archived scanner passes 460 tests, including 60 new focused tests, and all 190 vulnerable/fixed corpus pairs. The new corpus pair is self-authored regression coverage and is excluded from the supplied set's totals.

Pass 1 found four unsafe binding assumptions: inherited properties, namespace-scoped imports, SDK-excluded declarations and pattern variables. Pass 2 found six more: invisible interface decoys, LINQ continuations, file-local types, reserved receivers, implicit setter values and inherited properties in default interface methods. Each was fixed and covered by public scanner regressions. The second reviewer replayed all 12 preserved adversarial fixtures against the exact baseline/final snapshots; every baseline SQL warning remains. Separate owner-shape probes retain warnings in all seven unsupported non-class forms and preserve the ordinary-class positive control. A clean aggregate benchmark score alone would have missed these defects.

The remaining controller warning needs scoped framework member/type resolution. Adding exceptions based on a class name alone is unsafe: inherited properties can hide an imported type with the same name. Native C needs an explicit analysis path before its labels can earn accuracy credit.

## Frozen evidence

All seven established suites were rerun for the pinned baseline and final implementation. Input hashes, labels, evaluator identities, policies, options and every scoring unit match. There are zero transitions in either direction, including zero lost true positives and zero new false positives.

| Dataset | Units | TP before → after | FP before → after |
|---|---:|---:|---:|
| Juliet C# 1.3 | 59,282 | 1,036 → 1,036 | 470 → 470 |
| OWASP Java 1.2 | 2,740 | 571 → 571 | 289 → 289 |
| Juliet Java 1.3 | 57,649 | 2,410 → 2,410 | 1,172 → 1,172 |
| SARD PHP 115 | 20 | 10 → 10 | 0 → 0 |
| CVE snapshots, original policy | 16 | 1 → 1 | 1 → 1 |
| Supplied labeled apps | 227 | 87 → 87 | 11 → 11 |
| Earlier .NET labeled apps | 230 | 32 → 32 | 1 → 1 |

Original CVE pair success remains 0/8; the separately localized policy remains 1/8. SARD has no safe denominator. These previously exposed suites remain separate evidence tiers and do not establish production accuracy.

The earlier frozen key was also replayed unchanged: both profiles retain 2 TP, 8 FN, 0 FP and 20 TN for C#, plus 18 unsupported C cases. FinSuite still produces zero raw candidates in either profile; this is a compatibility check, not credit for its previously documented business-logic gap. The final source snapshots, input manifests and cases were verified again after measurement.

Juliet C# scanner time was 97.664s → 108.382s (1.110×), within the predeclared 1.5× gate. Preparation/hashing is additional, jobs shared the machine, and one run per phase is not a robust performance estimate. The [aggregate evidence](benchmarks/const-member-sql-results.json) records the counts, transitions, hashes, options and separate policies.

Baseline commit: `8d3ffb9bf98d50ee28a1667a33f680594001f072`; scanner byte hash `678dc4fcf418ef6705c799fe44310fc57c5e0a367439bafe80f2e9a9019e62cd`.

Final measured commit: `9e065d04702c835ea0e3b34fe0f9773e50c21f9e`; scanner byte hash `b4a03c4c3bdb8ca387e9b340c3fe659e90c58dd24e571a2025e7d0f00a4cfa62`.

All 952 baseline and 963 final tracked files were checked against Git blobs. Exact archive/inventory hashes identify the scanned bytes; CRLF-to-LF normalization was allowed only when comparing UTF-8 source to Git. The new module has LF in the working copy and CRLF in the archive; its text is otherwise identical. Tests also ran on the exact archived bytes. Later documentation commits are outside that snapshot.

Local evidence is retained under the parent workspace's `output/claude-safe-apps-2026-10-23`: original bundles, freeze inventory, keys, policies, raw reports, scores, baseline/intermediate/final snapshots, test logs, both reviews and adversarial probes. Intermediate revisions `369093e` and `c36caa7` were rejected after review and are not shipping evidence. Their artifacts remain intact. Target source, answer keys and raw findings remain local; only aggregates are published.

Reproduce the seven suites using the commands in [PYTHON-VALUE-PRECISION.md](PYTHON-VALUE-PRECISION.md#reproduction) with separate outputs, then compare using `scripts/compare-dotnet-accuracy.js`. The retained local `measure.js`, `score.js`, `SCORING-ADDENDUM.md`, `measure-prior-frozen.js` and `run-benchmarks.js` record the supplied-set and compatibility protocol. Each scanner phase was scored once; review-driven fixes and retired intermediate phases remain in the execution ledger. No key or dataset was tuned to the scanner.

### Language references

- [Constant interpolated strings](https://learn.microsoft.com/en-us/dotnet/csharp/fundamentals/strings/interpolation#build-constant-strings)
- [C# keywords and contextual keywords](https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/)
- [ControllerBase API](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.mvc.controllerbase?view=aspnetcore-10.0)
