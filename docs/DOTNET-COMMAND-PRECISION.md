# .NET command-injection proof follow-up

This follows PR #19. The objective is fewer incorrect command alerts while preserving existing detections. The changes improve supported command expressions and repair a suppression bug; they do not establish independent accuracy. Existing benchmark labels and scoring policies remain frozen.

## Changes

- Check both executable and argument expressions in a two-argument `Process.Start` call. Each must be proved constant.
- Check every recognized command sink on a line. A constant first call must not hide a later dynamic call or `.Arguments` assignment.
- Follow conditional and null-coalescing expressions only when every possible result is proved constant. An unknown condition is allowed; an unknown result is not.
- Resolve the exact C# keyword alias `using String = string;` in a narrowly closed scope. Require one non-partial root type, no namespace, no inheritance, and no `<` tokens anywhere in the file. This last restriction also rejects less-than comparisons conservatively. Imported `String`, `System.String`, contextual `var`, custom types and uncertain aliases gain no new proof.
- Reject named helper arguments rather than assuming their textual position equals their parameter position. Existing mutation, caller-visibility, recursion and ownership checks remain in force.

New overloads and multiple-sink lines use the stricter scoped value proof. They do not inherit the older direct-literal proof's acceptance of unaliased `String` and `var`. That older single-expression behavior is a remaining semantic-binding gap; this change does not claim to repair it across referenced assemblies.

No runtime dependency was added. Targets are read statically, and their code, builds, generators and package scripts are not executed. Experimental project findings remain opt-in.

## Why the remaining Juliet command cases are blocked

The fresh baseline has **200 CWE-78 false-positive units**, containing **220 matched sites**. Every matched site is in a file that declares the command prefix as `String osCommand`.

| Structure | Units | Missing proof |
|---|---:|---|
| Same-file variants 21, 31, 41, 42 and 45 | 50, ten per variant | Resolve the command prefix's named type without accepting custom conversion/operator behavior |
| Cross-file variants 22, 51–54, 61, 66–68, 71–75 and 81 | 150, ten per variant | Resolve the named prefix and establish a complete argument/state flow across files |

`using System` does not prove that bare `String` denotes the framework type. An enclosing namespace, alias, inherited nested type or referenced assembly can supply another type. A complete inventory of scanned source files still cannot rule out those cases. Treating absence of a source declaration as a positive binding proof would suppress some real bugs.

A separate static counterfactual replaced only `String osCommand` with the built-in keyword spelling in memory. All 50 same-file units then passed the existing value proof. This isolates the type-binding blocker; **it is not a benchmark result or an achieved reduction**. Benchmark input files and labels were not changed. The [diagnosis record](benchmarks/dotnet-command-gap-diagnosis.json) records the variant counts and scope of that experiment.

The next route to those 50 cases is a trustworthy semantic binding for the command prefix. It must account for aliases, namespace and nested-type lookup, base types, generic parameters, referenced metadata and source-generation/project completeness. Unsupported or incomplete binding must retain the warning. The remaining 150 additionally need complete caller/state summaries; a truncated graph cannot justify suppression. A benchmark-specific spelling or filename exemption is not an acceptable shortcut.

## New regression evidence

The new vulnerable/safe corpus pair is **self-authored after reading the rules and benchmark results**. Scanning it with the archived baseline and final engines preserves both vulnerable finding sites and removes both safe finding sites: **two safe alerts → zero**, **two vulnerable alerts → two**. These are finding-site counts from one new pair, not additional Juliet cases, an independently authored set, or production precision evidence. The [regression artifact](benchmarks/dotnet-command-regression-comparison.json) records source and input hashes and the exact sites.

Focused tests also retain a dynamic second argument, unknown branch result, reassignment, a later unsafe sink on the same line, reordered named helper arguments and custom/inherited `String` forms. Sanitizer names alone still do not grant command safety.

## Juliet C# results

The completed comparison has **zero unit transitions**. The objective of reducing the existing command false positives was **not achieved in this pass**.

| Measure | Before | After |
|---|---:|---:|
| Units, all CWEs | 59,282 | 59,282 |
| TP | 1,036 | 1,036 |
| FP | 470 | 470 |
| TN | 29,131 | 29,131 |
| FN | 28,645 | 28,645 |
| Recall | 3.49% | 3.49% |
| FPR | 1.59% | 1.59% |
| Precision | 68.79% | 68.79% |

CWE-78 alone remains **370 TP, 200 FP, 180 TN and 10 FN** across 760 units: 97.37% recall and 52.63% FPR. Its high recall does not offset that false-positive rate. The full-suite denominator includes many currently undetected CWEs and must not replace the per-CWE result when assessing command precision.

C# scanner duration was **94.820s → 99.928s**, a 1.054× ratio within the existing 1.5× default-scan budget. Manifest preparation and hashing add wall time outside that duration. These are single shared-machine runs, not a robust throughput estimate.

## All benchmark results

All seven datasets were rerun before and after, using the same inputs, labels, scoring policies, options and evaluator logic. The C# evaluator and runner differ only in LF/CRLF line endings between checkouts; measured scanner hashes cover the evaluator source bytes. The supplied-app evaluator has an identical separately recorded byte hash in both phases. The [comparison artifact](benchmarks/dotnet-command-precision-comparison.json) records the hashes, per-unit comparisons, per-CWE C# metrics and scan diagnostics. **Every dataset has zero FP→TN, TP→FN, TN→FP and FN→TP transitions.** No datasets or scoring policies are pooled.

| Dataset | Units | TP before→after | FP before→after |
|---|---:|---:|---:|
| Juliet C# 1.3 | 59,282 | 1,036→1,036 | 470→470 |
| OWASP Java 1.2 | 2,740 | 571→571 | 289→289 |
| Juliet Java 1.3 | 57,649 | 2,410→2,410 | 1,172→1,172 |
| SARD PHP suite 115 | 20 | 10→10 | 0→0 |
| CVE-fix snapshots, original policy | 16 | 1→1 | 1→1 |
| Supplied apps | 227 | 87→87 | 11→11 |
| Additional self-authored .NET apps | 230 | 32→32 | 1→1 |

SARD has no safe denominator, so its FPR is unmeasured. Complete CVE-pair success remains **0/8** under the original policy and **1/8** under the separately versioned source-region policy. App counts cover their existing labels; unmatched findings are unclassified. The Razor false positive remains. The earlier opt-in project diagnostic was not remeasured in this follow-up; no project-analysis implementation changed, and its truncated graph and unmet gates remain documented in the earlier report.

## Measurement protocol

The before engine is merged main commit `487ae8d5d20f9ca0964f3e75476b7882103303a9`, archived to a separate ignored directory. The measured baseline bytes hash to `67fa657fcfc6b71be93c80934f0f9b885e9567364f051dae0bb5f5a5f47d9cc6`. The archive matches that commit after line-ending normalization; raw hashes identify the measured bytes.

The final implementation is commit `95edb2d1dfb5d2b2d404cce03393d47514c1b980`, with measured scanner byte hash `d06f45a31aa1e839ff96f8d436e1e8daf3dc8e0d6f1d17cb30b4869285009c5f`. Aborted pre-review runs are excluded. Each completed dataset has the same engine hash within its phase, stable input hashes, identical labels, policies and options, and unchanged evaluator logic. The reviewer compared evaluator sources separately, accounting for the C# line-ending differences. Comparisons inspect unit transitions rather than totals alone.

The seven existing datasets retain their established tiers. Juliet and OWASP are seen third-party synthetic development data. The supplied labeled apps and the new pair are self-authored regression evidence. CVE snapshots are real upstream source under the existing two separately reported policies. No independent holdout is claimed.

### Reproduction

Restore the existing inputs using [the benchmark guide](BENCHMARKS.md), [Juliet/SARD guide](JULIET-SARD.md), [CVE guide](CVE-FIX-CORPUS.md) and supplied-app archives. At each declared engine commit, use the same input paths and separate output roots. For example, with `OUT` denoting that phase's output directory:

```console
node scripts/score-dotnet-juliet.js INPUTS/juliet-csharp-1.3 OUT/csharp
node bin/kayfabe.js benchmark owasp-java INPUTS/owasp-java --out OUT/owasp-java
node bin/kayfabe.js benchmark juliet-java INPUTS/juliet-java-1.3/Java --out OUT/juliet-java
node bin/kayfabe.js benchmark sard INPUTS/sard-115 --out OUT/sard
node bin/kayfabe.js benchmark cve-fixes INPUTS/cve-downloaded --out OUT/cve-fixes
node scripts/score-supplied-apps.js INPUTS/supplied-apps OUT/supplied.json
node scripts/score-supplied-apps.js INPUTS/additional-dotnet-apps OUT/dotnet-apps.json
node scripts/compare-dotnet-accuracy.js BEFORE AFTER comparison.json 487ae8d5d20f9ca0964f3e75476b7882103303a9 95edb2d1dfb5d2b2d404cce03393d47514c1b980
```

The comparison rejects mismatched inputs, labels, options, policies, separate evaluator hashes where recorded, or mixed engine hashes within a phase. CLI evaluator source shares the scanner hash and therefore also requires a source comparison across phases; this was independently reviewed. Preserve raw reports locally; the committed comparison includes SHA-256 hashes of their canonical JSON.

## Review record

Pass 1 examined suppression correctness and adversarial variants. A reordered named helper call exposed positional parameter confusion after ternary support; named arguments now fail closed. It also found qualified and escaped bases omitted by the project index. The alias guard now inspects the raw type header for inheritance.

Pass 2 independently examined type ownership and measurement provenance. It found that a generic base could be omitted by the index and evade a short lookahead. The proof now rejects generic angle syntax throughout the file, and inheritance is checked directly from header tokens. Both defects have failing-then-passing regression reproductions, including padded, `global::`, escaped and alias-qualified base names.

The full tests and corpus run pass: **309 tests and 176 vulnerable/safe pairs**. These checks do not replace the benchmark comparison or the unmeasured independent, public-repository, parser-completeness and project-graph gates documented in the [roadmap execution report](DOTNET-ACCURACY-ROADMAP.md).
