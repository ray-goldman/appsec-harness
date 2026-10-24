# MVC constant-member SQL precision

This change extends the literal constant-member SQL proof to one modeled framework base: direct `Microsoft.AspNetCore.Mvc.ControllerBase` inheritance in a standard `Microsoft.NET.Sdk.Web` / `net10.0` project. It refines only the existing complete `CommandText` interpolation shape; it does not sanitize request input or general SQL assembly.

## Binding and fallback

The pinned profile contains 67 conservative inherited names from the .NET 10 MVC shipped/unshipped API declarations and the `System.Object` reference declaration. A receiver such as `Request`, `HttpContext`, `User` or `Response` cannot bind an imported constant type through this proof. All existing unique source-type, literal-const, visibility, value-shadow, interpolation, expression, same-line sink, namespace, project-completeness and input-budget checks still apply.

The framework base must be directly visible through a MVC import/current namespace, or use either exact qualified spelling. Competing source type names for `Microsoft`, `AspNetCore`, `Mvc` or `ControllerBase` decline, even if inaccessible. Additional bases, custom subclasses, `Controller` view inheritance, unknown targets, explicit build/framework overrides, aliases and unsupported owner shapes retain warnings. Source-interface-only behavior from the previous proof remains unchanged.

The profile models the standard .NET 10 API contract. A target-framework string does **not** verify the installed SDK/reference-pack version. Replacement assemblies, unobserved compiler inputs and future framework API additions outside this profile are not proved. This is a source/model subset, not compiler validation or a soundness claim for arbitrary builds. These assumptions follow the existing standalone-project proof boundary.

The [profile](../src/frameworks/aspnetcore-controllerbase-net10.json) records immutable upstream URLs and SHA-256 hashes. Sources are ASP.NET Core v10.0.0 commit `7387de91234d3ef751fa50b3d1bfede4130213ff` and runtime v10.0.0 commit `60629d14374c56f1cb51819049ad1fa529307f8d`. No downloaded upstream code is executed and the scanner performs no profile lookup over the network. No dependencies were installed.

## Unchanged frozen key

| Each profile, default and experimental project | Release baseline | Implementation |
|---|---:|---:|
| Raw C# warnings | 1 | 0 |
| Labeled FP cases | 1 | 0 |
| Labeled TN cases | 19 | 20 |
| Case false-positive rate | 5% | 0% |
| Unmatched warnings / unresolved ties | 0 / 0 | 0 / 0 |
| Native C unsupported cases | 12 | 12 |
| Native C TN credit | 0 | 0 |

The removed controller warning interpolates a visible literal `const string`; request values remain bound SQL parameters. The earlier service correction remains in effect. Both profiles have exactly one FP-to-TN transition under the unchanged key/scorer/policy. No labels, target source or denominators changed.

This supplied set contains only 20 safe C# and 12 unsupported native C cases. Its provenance records prior scanner exposure and same-session authorship/reviews. It remains development evidence, neither independent nor blind; it measures no recall. A zero rate here does not establish production accuracy or support for native C.

## Regression and benchmark evidence

Four public safe-case regressions failed before implementation, then passed. Dynamic request interpolation, mutable fields and inherited/value-binding collisions retain warnings. The new vulnerable/fixed corpus pair is self-authored regression coverage and is excluded from the frozen set's totals.

The exact archived implementation passes 512 tests on Windows: 509 pass, zero fail and three explicit filesystem fixture skips. All 191 vulnerable/fixed corpus pairs pass. The first reviewer independently passed 93 focused tests and 34 additional scanner probes, reproduced the four upstream source hashes and the 67-name closure, and found no actionable issue. Adversarial fixtures are scanner inputs; C# applications are not compiled or executed.

The second fresh review found no actionable issue after 93 focused tests, 143 new probes and retention of all 12 earlier adversarial warnings. It independently reproduced the profile, verified source/input/scoring provenance, recounted every benchmark unit and checked the public aggregate/prose against the final reports. Both reviews completed before opening the PR.

All seven established suites were rerun against release `v1.0.1` with unchanged labels, datasets, evaluators, options and scoring policies. Every scoring-unit outcome is unchanged, including zero lost true positives and zero new false positives. Final per-unit comparisons and timing are retained in the [aggregate evidence](benchmarks/mvc-constant-sql-results.json).

| Dataset | Units | TP before → after | FP before → after |
|---|---:|---:|---:|
| Juliet C# 1.3 | 59,282 | 1,036 → 1,036 | 470 → 470 |
| OWASP Java 1.2 | 2,740 | 571 → 571 | 289 → 289 |
| Juliet Java 1.3 | 57,649 | 2,410 → 2,410 | 1,172 → 1,172 |
| SARD PHP 115 | 20 | 10 → 10 | 0 → 0 |
| CVE source snapshots, original policy | 16 | 1 → 1 | 1 → 1 |
| Supplied labeled apps | 227 | 87 → 87 | 11 → 11 |
| Earlier .NET labeled apps | 230 | 32 → 32 | 1 → 1 |

The earlier frozen key retains 2 TP, 8 FN, 0 FP and 20 TN for C# in both profiles; its 18 native C cases remain unsupported. Raw finding identities are unchanged, including zero FinSuite candidates. That does not resolve FinSuite's documented business-logic gap. Full-suite Juliet C# recall remains 3.49%; this proof does not improve recall.

Juliet C# scanner duration was 116.610s → 106.339s (0.912×), within the 1.5× gate. Preparation/hashing adds time, jobs shared the machine and each phase ran once. This is not a robust speed-improvement measurement.

Original CVE pair success remains 0/8 and the localized policy remains 1/8, reported separately. SARD has no safe denominator. Previously exposed synthetic/real-source suites and self-authored app evidence are not pooled into an independent accuracy claim.

## Source identities and reproduction

Baseline: `17a0a940b4bba0a422dbee54e98bbcfd42d453b7`, byte hash `b6f1aaee59f54f2274db49ba49166b77fc45a58f3337a85eb7784b8d2046082a`.

Measured implementation: `dd76d3c6ddcedc37a9b18fa5e7fb22d2c54884da`, byte hash `d9304d080230d18018859dedea6c55aa987c0c55715bb942bee7ea4f794ca6ab`.

The 972 baseline and 984 final snapshot files were checked against Git blobs. Archive/inventory hashes identify exact scanned bytes; only UTF-8 CRLF-to-LF normalization is allowed when comparing to Git. Tests also ran on the exact archived bytes. Later evidence-document commits are outside the measured snapshot.

Use the seven commands in [PYTHON-VALUE-PRECISION.md](PYTHON-VALUE-PRECISION.md#reproduction) with separate before/after outputs, then `scripts/compare-dotnet-accuracy.js`. Local `output/mvc-constant-sql-2026-10-23` retains the premeasurement protocol, source archives, original API sources, profile derivation, inventories, test logs, all benchmark reports and review probes. New-set and earlier-key measurements reuse the unchanged local evaluators and frozen inputs under `output/claude-safe-apps-2026-10-23`. Target source, keys and raw reports remain local; public artifacts contain sanitized aggregates only.
