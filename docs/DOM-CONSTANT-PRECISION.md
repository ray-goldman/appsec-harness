# JavaScript fixed-markup proof

This pass adds a bounded proof for `JS-XSS-001`: a DOM write whose possible values are all fixed primitives does not need an injection alert. It does not infer safety from helper or sanitizer names. Application audits that motivated the investigation remain local; the committed fixtures are invented regression examples.

## Supported expressions and limits

The optional vendored Acorn parser must parse the complete JavaScript module or script. Supported files are `.js`, `.mjs` and `.cjs`, up to 200,000 UTF-8 bytes, 50,000 AST nodes and depth 160. Missing parser, parse failure, unsupported syntax or an exceeded budget retains the existing warning. TypeScript and embedded scripts receive no new proof.

The proof accepts string, number, boolean and null literals; template literals with only proved primitive interpolations; addition of proved primitives; and conditional, null-coalescing or logical-OR expressions whose possible outputs are all proved primitives. A dynamic condition may choose between two fixed outputs. Identifiers, calls, objects and custom coercions are not proved.

Every recognized DOM operation overlapping a reported line must pass. The proof checks assignments to `innerHTML` and `outerHTML`, `insertAdjacentHTML`, member calls named `write`/`writeln`, and the recognized jQuery-style insertion methods. It conservatively considers all receivers. Computed literal member names are recognized; unknown computed writes/calls, destructuring writes and member/pattern iteration targets prevent suppression on overlapping lines. Compound HTML assignments remain flagged. Bare CR and Unicode line separators disable the proof because parser and scanner line numbering differ; ordinary CRLF is supported.

The existing rule's name-based exclusions are unchanged. This pass does not establish that a sanitizer is correct, recognize dynamic HTML-building helpers, or provide whole-program XSS analysis.

## Regression evidence

The new paired corpus case covers fixed branch outputs versus dynamic markup. Focused tests include hostile same-line sinks, computed members, receiver chains, unsupported expressions, destructuring/iteration writes, parser budgets and line-ending mismatches. All **316 tests pass**, and all **177 vulnerable/fixed corpus pairs** retain 100% regression precision and recall. These self-authored examples are regression evidence, not independent accuracy evidence.

The [pair comparison](benchmarks/dom-constant-regression-comparison.json) records the exact fixture byte hashes and finding sites. The baseline flags both variants at line 2; the final engine retains the vulnerable alert and removes the safe alert. This pair is excluded from the seven existing benchmark totals.

## Seven existing benchmark results

All seven completed comparisons have **zero unit transitions**: no FP-to-TN, TP-to-FN, TN-to-FP or FN-to-TP changes. The new proof improves the invented DOM pair, but does **not** improve these existing benchmark scores. The [comparison artifact](benchmarks/dom-constant-precision-comparison.json) records per-unit transitions, input/engine hashes and scan diagnostics.

| Dataset | Units | TP before -> after | FP before -> after |
|---|---:|---:|---:|
| Juliet C# 1.3 | 59,282 | 1,036 -> 1,036 | 470 -> 470 |
| OWASP Java 1.2 | 2,740 | 571 -> 571 | 289 -> 289 |
| Juliet Java 1.3 | 57,649 | 2,410 -> 2,410 | 1,172 -> 1,172 |
| SARD PHP suite 115 | 20 | 10 -> 10 | 0 -> 0 |
| CVE-fix snapshots, original policy | 16 | 1 -> 1 | 1 -> 1 |
| Supplied apps | 227 | 87 -> 87 | 11 -> 11 |
| Additional self-authored .NET apps | 230 | 32 -> 32 | 1 -> 1 |

Complete CVE-pair success remains **0/8** under the original policy and **1/8** under the separately versioned source-region policy; its localized units also have zero transitions. Unmatched app findings remain unclassified. The original benchmark gaps remain, including low full-suite C# recall and the existing Razor false positive. No project-analysis implementation changed or new project-analysis claim is made.

C# scanner duration was 101.529s -> 95.709s (0.943x), within the existing 1.5x scan budget. These single shared-machine runs do not establish a speed improvement; input preparation/hashing adds wall time beyond scanner duration.

## Measurement protocol

The baseline is merged main commit `2f0ba0f10646c9fa783af954fb076f0b4eeceede`, archived into an isolated directory. Its measured scanner bytes hash to `7eff043bc7f506fb2c43d4ec0a3825949cc0c9283eaec8835e497a81c4493c87`.

The frozen implementation is commit `0baee628f3968b6ea461d6baa347cc0416712999`; its measured scanner bytes hash to `fa16edc300ff0cc28199d12c9a26f37f5dfc40c8056f480aea28923b3c7dbcda`. Documentation is committed separately. A reviewer compared the baseline source/evaluators with the declared baseline commit after CRLF normalization. Raw hashes identify the actual measured bytes.

Each phase reruns seven existing datasets with unchanged inputs, labels, policies, options and evaluator logic. Unit transitions must be compared, not just totals. Separate evaluator hashes are checked where recorded; CLI evaluators share the scanner hash and require source comparison. Raw reports remain local; the committed comparison records their canonical JSON hashes.

Dataset tiers stay separate: Juliet/OWASP are previously seen third-party synthetic development data; CVE snapshots are upstream real source scored under two distinct existing policies; supplied labeled apps are self-authored regression data. No independent holdout or pooled accuracy claim is made. SARD has no safe denominator, so its false-positive rate is unmeasured.

## Review record and deferred work

Two review passes inspected the removal proof and adversarial variants. They found and prompted fixes for computed member overlap, qualified `document.write` calls, mismatched line endings, destructuring writes and iteration targets. Both source reviews cleared the final implementation before the benchmark freeze.

A Python constructor-identity experiment was withdrawn after review found mutation and aliasing paths that invalidated its assumptions. Python source handling is unchanged. Future helper/sanitizer improvements need explicit ownership and mutation evidence; a familiar function name alone is insufficient.

### Reproduction

Restore the existing inputs following [the benchmark guide](BENCHMARKS.md), [Juliet/SARD guide](JULIET-SARD.md) and [CVE guide](CVE-FIX-CORPUS.md). Run each engine in its own checkout with separate output directories:

```console
node scripts/score-dotnet-juliet.js INPUTS/juliet-csharp-1.3 OUT/csharp
node bin/kayfabe.js benchmark owasp-java INPUTS/owasp-java --out OUT/owasp-java
node bin/kayfabe.js benchmark juliet-java INPUTS/juliet-java-1.3/Java --out OUT/juliet-java
node bin/kayfabe.js benchmark sard INPUTS/sard-115 --out OUT/sard
node bin/kayfabe.js benchmark cve-fixes INPUTS/cve-downloaded --out OUT/cve-fixes
node scripts/score-supplied-apps.js INPUTS/supplied-apps OUT/supplied.json
node scripts/score-supplied-apps.js INPUTS/additional-dotnet-apps OUT/dotnet-apps.json
node scripts/compare-dotnet-accuracy.js BEFORE AFTER comparison.json 2f0ba0f10646c9fa783af954fb076f0b4eeceede 0baee628f3968b6ea461d6baa347cc0416712999
```
