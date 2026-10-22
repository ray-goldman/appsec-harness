# .NET accuracy roadmap execution

This work follows the [four-step plan](superpowers/plans/2026-10-21-dotnet-accuracy-next-four-steps.md) and the existing evaluation policy. Benchmark results are development evidence; neither the regression apps nor the observed Juliet cases are an independent holdout.

## Measurement and classification

All seven baseline datasets were recovered locally and rescanned with the merged-main scanner source hash `b238e68f1a932835f8852ee85543e437018402358ba33eadf6e40b9e23fce30b`. The baseline scanner was copied to an ignored snapshot, with source-hash equality checked, allowing implementation to proceed while baseline measurements completed. Incomplete runs were discarded. Scanner hashes and input hashes are verified before and after each labeled benchmark.

The C# baseline is 1,036 TP, 560 FP, 29,041 TN and 28,645 FN. The 560 FPs consist of 200 command-injection and 360 SQL-injection units. Grouping repeated cases by flow structure identifies five same-file groups of 28 units each:

| Flow structure | Units | Missing proof |
|---|---:|---|
| Helper returns with branch assignments (21) | 28 | Every possible returned value is constant |
| Disjoint local blocks (31) | 28 | Distinguish same-spelled locals by lexical scope |
| Helper sink parameters (41) | 28 | All resolved private callers supply constant values |
| Helper returns, including unused parameters (42) | 28 | Returned values do not depend on dynamic arguments |
| Private fields (45) | 28 | Every relevant field write is constant |

The other 420 units involve cross-file helpers, static state, collections or polymorphic dispatch (22, 51-54, 61, 66-68, 71-75, 81). Their labels are unchanged. Shared template structure is one root cause repeated across multiple inputs, not many independent validations of generalization.

## Proof boundaries

The additional proof is bounded to one non-partial type, at most 256 methods and 20,000 tokens, with expression and recursion limits. It uses existing lexical/parser spans and rejects uncertain ownership. Private helper calls must have one supported target; public/protected caller suppression is unavailable. Helper results must have built-in scalar return declarations and every return must be proved. An unused parameter can be dynamic without making a literal return dynamic.

New local, parameter and field proofs accept built-in scalar keywords only. Ambiguous `String` and contextual `var` declarations remain unknown in this additional model. In particular, the generated command-prefix locals spelled `String` prevent some otherwise plausible Juliet suppressions. A spelling-only alias assumption can hide custom conversions, so those cases need type-resolution work before they can be removed. The legacy literal proof retains its existing scope, with tuple writes and explicit alias declarations now invalidating its proof.

Field proofs require private built-in scalar declarations, complete visibility of relevant writes, and no unsupported body or shadow binding that could hide a write. Expression-bodied setters, property bodies, ref/out uses, deconstruction, compound writes, interpolation, recursion, partial types and ambiguous declarations retain warnings where they obstruct proof. Pattern and unsupported dispatch forms are not treated as safe. The proof is a bounded extension of the existing analyzer, not full C# semantic type checking.

Sanitizer names alone establish no safety. The regression tests retain findings for passthrough `EscapeArgument` and `HtmlEncode` helpers, including HTML encoding used at a SQL sink. No additional general sanitizer was enabled without an established safe-value proof.

## Project analysis and runtime

Request values and parameter aliases are tracked through supported straight-line local assignments. Unknown writes kill previous values. Mixed parameter/request expressions retain both facts. Private constant-only callers can remove parameter flows only under the existing visibility/ownership rules. Public methods retain low-confidence external exposure when visible callers do not establish a high-confidence request source.

The versioned summary engine now deduplicates semantic source/sink facts instead of growing call paths repeatedly. Distinct sink locations stay distinct. Recursion with argument permutations can introduce new parameter flows; repeated method IDs alone do not terminate propagation. Source confidence remains separate from whether a graph was truncated.

DI resolution supports a unique visible interface implementation and retains unresolved alternatives in explicit registrations. Same-name and equal-arity ambiguities remain unresolved. Type suffix lookup is indexed instead of repeatedly scanning the whole project type list.

The pre-change project run reached the index and summary engine, then failed to complete downstream. A standalone regression isolated a route regex timeout on 100,000 masked comment characters. Removing overlapping leading whitespace repetitions makes that case complete within its two-second test budget. This is a harness-only test; target code is never executed.

## Evaluation gates

The frozen default target is at most 420 C# FPs, all 1,036 existing TPs retained, and no newly flagged safe units. The approved cross-file target remains at least 60% recall on the existing cross-file subset. Runtime is evaluated separately for default and opt-in scans; the project profiling budget is 600 seconds with a 4 GiB Node heap. Fixed project limits are preserved instead of raised to make a partial graph appear complete.

The independent-author and adjudicated public-repository gates remain unmeasured: no qualifying isolated author, frozen 30-50 repository sample or two-adjudicator sample is available. WebGoat.NET/eShop input and adjudication are also unavailable here. This work cannot satisfy those gates. Missing evidence must not be replaced by generated applications or inferred precision. Project findings remain opt-in.

The existing self-authored .NET app set has one known false positive at `mvc-shop/Views/Products/Details.cshtml:12`: `Html.Raw` receives explicitly HTML-encoded text. The zero-FP app gate therefore remains failed. Razor context and parser coverage are separate work; this C# method proof does not infer that HTML encoding is safe in script or attribute contexts. Parser counts remain scanner-reported structural completeness, not a verified grammar-coverage gate. Confidence-stratified benchmark counts are unmeasured because the frozen matching reports do not retain per-finding confidence.

## C# results

The final scanner source SHA-256 is `74ff507fd07d40014a87ec2f539f65a7b79c68be8af02720c4fb4ae4260ae305`, from implementation commit `f8d5fc4a75a6398ec7e4f90dc4c42d0c62070c47`. These are byte hashes from the Windows run; line-ending normalization can change the hash on another platform.

| All 59,282 Juliet C# units | Before | After |
|---|---:|---:|
| TP | 1,036 | 1,036 |
| FP | 560 | 470 |
| TN | 29,041 | 29,131 |
| FN | 28,645 | 28,645 |
| Recall | 3.49% | 3.49% |
| FPR | 1.89% | 1.59% |
| Precision | 64.91% | 68.79% |

Every unit was compared by ID: **90 FP→TN, zero TP→FN, zero TN→FP and zero FN→TP**. This is a **16.07% FP reduction**, missing the frozen 25% planning target. All reductions are in CWE-89 (360→270 FPs); CWE-78 remains at 200 FPs. The remaining command-prefix `String` bindings require type resolution. No labels, CWE aliases or denominators were changed to recover the target.

The all-CWE FPR includes many currently undetected categories. On the fixed diagnostic subset of **CWE-78 and CWE-89 only** (2,812 units), recall is 73.68% unchanged and FPR is **39.83%→33.43%**. This subset names the categories targeted by this change; it is not all supported .NET coverage and must not replace the full-suite denominator. Per-CWE FPR remains 52.63% for command injection and 26.32% for SQL injection, so substantial precision work remains.

Default scanner time was **96.505s→100.960s**, a 1.046× ratio within the existing 1.5× budget. These single end-to-end scan timings share a machine with other benchmark activity and do not establish a repeatable throughput change. Manifest preparation/hashing adds time outside the reported scanner duration.

## Project diagnostic results

The opt-in project run completed with **104.057s scanner time**, within the 600s profiling budget. It produced the same scored totals as the default scan and added **zero** labeled detections. The frozen cross-file subset remains **420/11,030 vulnerable units detected (3.81% recall)**, with 420 FPs among 11,030 safe units. The 60% recall gate fails.

This is an incomplete-graph diagnostic: the 100 MiB source collection and 50,000-method index limits were reached. Of 50,000 indexed methods, 32,272 were summarized and 17,728 were unsupported; 15,470 collected files fell back or were excluded by index limits. Only **50/12,755** recorded calls resolved. There were 35,909 unresolved summary sites, no newly propagated sink methods, and no project flow findings. These counts explain why the synthetic regression examples do not generalize to this full benchmark yet. They do not distinguish all missing source APIs, unsupported control flow and missing receiver identities.

The [project artifact](benchmarks/dotnet-project-accuracy-diagnostic.json) records input/label/source hashes, raw report hash, scan options, truncation, warnings and per-CWE totals. The default regex scan still covered the full labeled corpus; that coverage must not be mistaken for a complete project graph. Project findings remain behind `--dotnet-project-analysis`. The independently authored, real-repository, confidence and parser-completeness gates are not passed.

## Full benchmark matrix

All seven datasets were rerun before and after, with the same source hash within each phase. Input hashes, scorer policy, explicit options and labeled units match in the [comparison artifact](benchmarks/dotnet-accuracy-comparison.json). Every dataset except Juliet C# has zero unit-outcome transitions. Results from different datasets and scoring policies are not pooled.

| Dataset | Units | TP before→after | FP before→after |
|---|---:|---:|---:|
| Juliet C# 1.3 | 59,282 | 1,036→1,036 | 560→470 |
| OWASP Java 1.2 | 2,740 | 571→571 | 289→289 |
| Juliet Java 1.3 | 57,649 | 2,410→2,410 | 1,172→1,172 |
| SARD PHP suite 115 | 20 | 10→10 | 0→0 |
| CVE-fix snapshots, original policy | 16 | 1→1 | 1→1 |
| Supplied apps | 227 | 87→87 | 11→11 |
| Additional self-authored .NET apps | 230 | 32→32 | 1→1 |

SARD has no safe denominator and cannot measure FPR. CVE complete-pair success stays **0/8** under the original policy and **1/8** under the separately versioned source-region policy. The application labels are self-authored regression evidence; unmatched findings are unclassified. The existing one Razor FP is retained.

Both final review passes found no outstanding actionable source/scorer blockers after their fixes; the second reviewer checked these artifact counts and hashes separately. Verification is **303 unit tests and 175 vulnerable/safe corpus pairs passing**. These regression checks do not establish independent precision or recall.

## Reproduction

Restore the inputs using the existing [benchmark guide](BENCHMARKS.md), [Juliet/SARD guide](JULIET-SARD.md), [CVE guide](CVE-FIX-CORPUS.md), and supplied-app archives. Run the commands below in the baseline engine checkout (`80f6ac4f676b7c050c947a69b14a52f4d3ded995`) and the implementation checkout (`f8d5fc4a75a6398ec7e4f90dc4c42d0c62070c47`), using separate output directories. Use the updated supplied-app evaluator bytes in both checkouts; the comparison rejects a mismatched evaluator hash. The paths below assume inputs are restored under the conventional local ignored directories.

```console
node scripts/score-dotnet-juliet.js appsec-out/benchmarks/juliet-csharp-1.3 appsec-out/four-step/verified/csharp
node bin/kayfabe.js benchmark owasp-java appsec-out/benchmarks/owasp-java --out appsec-out/four-step/verified/owasp-java
node bin/kayfabe.js benchmark juliet-java appsec-out/benchmarks/juliet-java-1.3/Java --out appsec-out/four-step/verified/juliet-java
node bin/kayfabe.js benchmark sard appsec-out/benchmarks/sard-115 --out appsec-out/four-step/verified/sard
node bin/kayfabe.js benchmark cve-fixes appsec-out/cve-downloaded --out appsec-out/four-step/verified/cve-fixes
node scripts/score-supplied-apps.js appsec-out/supplied-benchmarks-2026-10-20/benchmarks/apps appsec-out/four-step/verified/supplied.json
node scripts/score-supplied-apps.js appsec-out/claude-dotnet-review/benchmarks/apps/dotnet appsec-out/four-step/verified/dotnet-apps.json
node scripts/score-dotnet-juliet.js appsec-out/benchmarks/juliet-csharp-1.3 appsec-out/four-step/project-verified --dotnet-project-analysis
node scripts/compare-dotnet-accuracy.js appsec-out/four-step/before appsec-out/four-step/verified docs/benchmarks/dotnet-accuracy-comparison.json 80f6ac4f676b7c050c947a69b14a52f4d3ded995 f8d5fc4a75a6398ec7e4f90dc4c42d0c62070c47
```

## Review record

Pass 1 uses a fresh correctness reviewer. Reproduced findings receive regression tests and fixes before final scoring: parameter reassignment; deconstruction; `??=` lexing; unsupported shadow bindings; delegate/receiver ownership; custom return/field conversions; mixed request/parameter confidence; and recursive parameter permutations. Additional negative tests cover expression-bodied/property writes and interpolated mutations.

Pass 2 checks source/input/scorer hashes, fixed labels, per-unit transitions, score denominators, default versus project results, runtime and claims. The comparison script rejects changed labels/policies/provenance and inconsistent outcomes instead of comparing totals alone.

The supplied-app evaluator now checks engine, evaluator and input hashes before and after scanning, preserving its existing `includeTests: true` options. Both baseline app sets were rerun with that exact evaluator. The published comparison retains scan options, warnings and diagnostics; its canonical report hash is SHA-256 of `JSON.stringify(report)`, rather than the on-disk indentation/newline representation.
