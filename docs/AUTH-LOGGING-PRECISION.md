# Authentication logging: browser navigation literals

`PROJ-LOGGING-001` is a low-confidence project heuristic. Previously, a browser redirect to `/login` could be the only authentication-looking text in a file, yet trigger a warning about missing security-event logging. This pass distinguishes a small supported set of navigation literals from authentication-code evidence.

## Retained change

For `.js`, `.mjs` and `.cjs` files, the optional vendored Acorn parser must parse the complete module or script. The refinement accepts only a standalone `=` assignment of a literal path to `location.href` or `window.location.href`, `document.location.href` or `self.location.href`. The decoded string must start with one slash, without a second slash, backslashes or ASCII whitespace/control characters. Executable schemes such as `javascript:` and `data:` are retained.

Only that literal is removed from the authentication hint search. Authentication identifiers, route declarations, computed dispatch keys, comparisons, call arguments, interpolated code and all other literals remain available to the existing heuristic. A real authentication hint elsewhere in the file still produces its warning unless the existing logging predicate matches.

Explicit owner shadowing, escaping or replacement retains hints. So do `with`, `this`, imports, recognized code-generation/reflection references, nonnumeric computed calls/writes, and directly called bindings initialized by computed reads. Files over 200,000 UTF-8 bytes, ASTs over 50,000 nodes or depth 160, missing parser and parse failures keep the original behavior. Other languages and TypeScript are unchanged.

This is a bounded syntax refinement under normal browser navigation semantics. It does not establish whole-program ownership of browser globals, complete reflection/alias analysis, actual logging reachability, or that an application audits every security decision. Unknown behavior outside the supported model still needs human review.

## Regression and review evidence

All **322 tests pass** and all **178 vulnerable/fixed corpus pairs** retain 100% regression precision and recall. These examples were authored with access to the scanner and development datasets; they are not independent accuracy evidence.

The [invented pair comparison](benchmarks/auth-logging-regression-comparison.json) records exact file byte hashes and finding sites. Both engines retain the vulnerable server authentication warning. The refined engine removes the browser navigation warning from both variants, while real logging in the fixed server still prevents its warning. These fixtures are excluded from the seven existing benchmark totals.

Two source review passes found concrete unsafe generalizations and prompted narrower handling:

- Generic logical fallbacks could become computed authentication dispatch keys. That exemption was removed entirely.
- Dynamic `with` scopes and replaced or aliased globals invalidated navigation assumptions. Added guards retain those hints.
- Executable URL literals and constructor-based reflection could hide code. Restricted the URL spelling and retained computed call/write and reflection cases.
- Broadly masking logging-looking string contents could add warnings when another API executes the string. That experiment was withdrawn. The existing logging predicate, including its data-string limitations, is unchanged.

Arbitrary display labels, mutable object fallbacks, Python docstrings/path provenance, dynamic HTML helpers and unknown callback effects remain deferred. A familiar name or a manually dismissed finding does not establish an automatic suppression rule.

## Seven existing benchmark results

All seven after runs completed. The [comparison artifact](benchmarks/auth-logging-precision-comparison.json) records **zero unit transitions** in every dataset: no FP-to-TN, TP-to-FN, TN-to-FP or FN-to-TP changes. This pass does not improve those existing benchmark scores. The invented browser-navigation fixtures show the supported improvement separately.

| Dataset | Units | TP before -> after | FP before -> after |
|---|---:|---:|---:|
| Juliet C# 1.3 | 59,282 | 1,036 -> 1,036 | 470 -> 470 |
| OWASP Java 1.2 | 2,740 | 571 -> 571 | 289 -> 289 |
| Juliet Java 1.3 | 57,649 | 2,410 -> 2,410 | 1,172 -> 1,172 |
| SARD PHP suite 115 | 20 | 10 -> 10 | 0 -> 0 |
| CVE-fix snapshots, original policy | 16 | 1 -> 1 | 1 -> 1 |
| Supplied apps | 227 | 87 -> 87 | 11 -> 11 |
| Additional self-authored .NET apps | 230 | 32 -> 32 | 1 -> 1 |

The separately versioned localized CVE policy also has zero unit transitions. Complete pair success remains **0/8** original and **1/8** localized. Unmatched app findings remain unclassified. Existing detection gaps and the Razor false positive remain; this pass makes no new project-analysis claim.

C# scanner duration is 95.709s -> 98.187s (1.026x), within the existing 1.5x scan budget. The baseline timing is reused from the prior run. These single shared-machine measurements do not establish a robust performance estimate; input preparation/hashing adds wall time outside scanner duration.

## Measurement protocol

The baseline is merged main `105967b8599189e830b611bd9855476fdcfc27f0`, with measured scanner byte hash `fa16edc300ff0cc28199d12c9a26f37f5dfc40c8056f480aea28923b3c7dbcda`. The before reports reuse the completed seven-dataset measurements from the preceding pass. An isolated baseline engine was reconstructed from that commit with the measured working-file line endings; its exact byte digest matches those reports. The measurement itself is unchanged; no new baseline timing run is claimed.

The frozen implementation is `f32d2c79559a2a73e4591c61a3f5290e15864100`, with measured scanner byte hash `3942c65d6c05e10f0ccfe9ef2c7eb43ff5335759c3102aa910813d03be0eedd9`. The package change only adds the new tests to `npm test`. Documentation is committed separately. All seven after datasets are rerun with this frozen engine.

Inputs, labels, scoring policies, options and evaluator logic must match. The comparison checks per-unit transitions and records canonical report hashes. Separate evaluator hashes are checked where available; CLI evaluators share the scanner hash and require a source comparison. Raw target audits remain local. Public fixtures and benchmark artifacts contain no target application source or findings.

Dataset tiers remain separate. Juliet/OWASP are previously seen third-party synthetic development data; CVE snapshots are upstream real source scored under two existing, separately reported policies; labeled supplied apps are self-authored regression evidence. No independent holdout or pooled accuracy claim is made. SARD has no safe denominator, so its false-positive rate is unmeasured.

### Reproduction

Restore the existing inputs using [the benchmark guide](BENCHMARKS.md), [Juliet/SARD guide](JULIET-SARD.md) and [CVE guide](CVE-FIX-CORPUS.md). Run each engine with the same input paths and separate outputs:

```console
node scripts/score-dotnet-juliet.js INPUTS/juliet-csharp-1.3 OUT/csharp
node bin/kayfabe.js benchmark owasp-java INPUTS/owasp-java --out OUT/owasp-java
node bin/kayfabe.js benchmark juliet-java INPUTS/juliet-java-1.3/Java --out OUT/juliet-java
node bin/kayfabe.js benchmark sard INPUTS/sard-115 --out OUT/sard
node bin/kayfabe.js benchmark cve-fixes INPUTS/cve-downloaded --out OUT/cve-fixes
node scripts/score-supplied-apps.js INPUTS/supplied-apps OUT/supplied.json
node scripts/score-supplied-apps.js INPUTS/additional-dotnet-apps OUT/dotnet-apps.json
node scripts/compare-dotnet-accuracy.js BEFORE AFTER comparison.json 105967b8599189e830b611bd9855476fdcfc27f0 f32d2c79559a2a73e4591c61a3f5290e15864100
```
