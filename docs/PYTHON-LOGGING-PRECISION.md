# Python audit messages and docstring evidence

This pass refines two existing heuristics: `PY-LOG-001` should distinguish fixed lifecycle-message text from logged credentials, and `PROJ-LOGGING-001` should distinguish supported documentation strings from authentication code. The existing rules and their other exclusions remain in place.

## Supported logging expressions

A new bounded lexical recognizer checks the complete call and every recognized logging call overlapping its line. It accepts a narrow literal grammar: an optional initial/account/UI descriptor, a password/token/secret lifecycle event (`changed`, `configured`, `created`, `updated`, `rotated` or `reset`), and optional source-address formatting. This is a finite message grammar, not a general claim that constant strings cannot contain secrets.

A message without formatting must have no additional arguments. The supported formatted message ends in `from %s`, with exactly one value: standard Flask `request.remote_addr`, optionally followed by `or "unknown"`. Credentials, raw request fields, arbitrary identifiers, extra keyword/positional arguments, interpolation, `.format`, percent expressions and other message text retain the existing warning. Formatted strings overlapping a line always prevent suppression, so an executable sink inside an f-string cannot hide behind an approved call.

The source-address model assumes normal Flask/Werkzeug semantics. It requires a complete source index within the existing walker/index limits, an unaliased `from flask import request`, and no indexed local Flask module/package. Detected binding changes, class/descriptor changes, custom `request_class`/`wsgi_app`, namespace mutation and unsupported request access retain warnings. Assignment, augmented assignment, unpacking, loop and context-manager targets are checked across logical statements, including multiline forms. It does not prove the absence of arbitrary external monkeypatching or custom import/runtime behavior.

## Supported documentation strings

Only a standalone, unprefixed, unescaped triple-quoted string used as the first module statement or first statement of a top-level, undecorated function can be removed from authentication-name evidence. Function headers must be on one physical line. Real authentication identifiers elsewhere remain visible. Methods, nested functions, class metadata, decorated functions, formatted/bytes/raw strings, concatenated literals, assigned text and semicolon-adjacent code retain their evidence.

Detected metadata access or dynamic execution (`__doc__`, `exec`, `eval`, `compile`, `getattr` and related namespace operations) disables this refinement. The existing logging-evidence predicate remains unchanged, including its known text-string limitations. This is a low-confidence authentication-hint refinement, not whole-program authorization or logging analysis.

## Bounds and regression evidence

The recognizer is implemented in Node and never imports or executes target Python. It is not a Python AST parser. It checks lexical string/bracket boundaries and the supported statement/call shapes; it does not validate the complete Python grammar. The limit is 200,000 UTF-8 bytes of comment-stripped code, 50,000 tokens and nesting depth 64. Unclosed strings/brackets, explicit line continuations, unsupported nested f-string forms, non-ASCII code identifiers and exceeded limits retain the original behavior. Unicode within ordinary strings is supported.

All **329 tests pass**, and all **180 vulnerable/fixed corpus pairs** retain 100% regression precision and recall. These examples were authored with access to scanner rules and development datasets and are regression evidence only.

The [invented-pair comparison](benchmarks/python-logging-regression-comparison.json) records input byte hashes, engine hashes and exact finding sites. The credential-logging alert stays at the vulnerable site while the safe address-format call loses its warning. The authentication decision stays flagged while the unrelated utility docstring warning disappears. These fixtures are excluded from the seven existing benchmark totals.

## Review record

Both source review passes cleared the final implementation after adversarial fixes:

- Case-insensitive and legacy logger spellings must participate in same-line checks.
- Decorator boundaries must use logical statements, including multiline decorators and intervening comments.
- Request-class overrides and all supported assignment target forms invalidate address provenance.
- A formatted string can execute a second logging sink on the same line; overlapping f-strings now retain warnings.

Class/method and nested-function docstrings remain deferred. Intentional credential provisioning, arbitrary message prose, mutable path provenance, dynamic HTML helpers and unknown callback effects receive no new suppression. Application source, findings and local comparisons remain local; public fixtures are invented examples.

## Seven existing benchmark results

All seven after runs completed with **zero unit transitions**: no FP-to-TN, TP-to-FN, TN-to-FP or FN-to-TP changes. The [comparison artifact](benchmarks/python-logging-precision-comparison.json) records the raw-report hashes, inputs, policies and per-unit checks. This pass does not improve those existing benchmark scores; the supported changes are demonstrated separately by the invented pairs.

| Dataset | Units | TP before -> after | FP before -> after |
|---|---:|---:|---:|
| Juliet C# 1.3 | 59,282 | 1,036 -> 1,036 | 470 -> 470 |
| OWASP Java 1.2 | 2,740 | 571 -> 571 | 289 -> 289 |
| Juliet Java 1.3 | 57,649 | 2,410 -> 2,410 | 1,172 -> 1,172 |
| SARD PHP suite 115 | 20 | 10 -> 10 | 0 -> 0 |
| CVE-fix snapshots, original policy | 16 | 1 -> 1 | 1 -> 1 |
| Supplied apps | 227 | 87 -> 87 | 11 -> 11 |
| Additional self-authored .NET apps | 230 | 32 -> 32 | 1 -> 1 |

The separately versioned localized CVE policy also has zero unit transitions. Complete pair success remains **0/8** original and **1/8** localized. Existing detection gaps, low full-suite C# recall and the Razor false positive remain. No new project-analysis claim is made.

C# scanner duration is 98.187s -> 93.787s (0.955x), within the existing 1.5x scan budget. The baseline timing is reused. These single shared-machine runs do not establish a speed improvement or robust performance estimate; preparation and hashing add wall time outside scanner duration.

## Measurement protocol

The baseline is merged main `097b27acae6ff1eeed79ed5f11a7645de6d3dbdf`, with measured scanner byte hash `3942c65d6c05e10f0ccfe9ef2c7eb43ff5335759c3102aa910813d03be0eedd9`. Before reports reuse the preceding completed seven-dataset run. A separate baseline engine was reconstructed from that commit with the measured working-file line endings, and its exact digest matches the reports. No new baseline timing run is claimed.

The frozen implementation is `d76d6f14fda4f12016ab61e59fc61a6225f06004`, with measured byte hash `e6c7fc2806cff151f758f2a2f28a0e66aab1fb3bc68b7777a260d5cccb7c01f7`. Documentation is committed separately. The package change adds the focused tests; evaluator logic is unchanged. Every after dataset is rerun with this engine.

Inputs, labels, policies, options and evaluator logic must match. The comparison checks per-unit transitions, records canonical raw-report hashes and rejects mixed engine hashes. Separate evaluator hashes are checked where available; CLI evaluators share the scanner hash and also require source comparison. The new `indexedComplete` metadata records source indexing before the existing namespace guard; it does not relax the existing helper proofs' `complete` requirement.

Dataset tiers stay separate: Juliet/OWASP are previously seen third-party synthetic development data, CVE snapshots are upstream real source scored under two existing policies, and labeled supplied apps are self-authored regression data. No independent holdout or pooled accuracy claim is made. SARD has no safe denominator, so its false-positive rate is unmeasured. Unmatched app findings remain unclassified.

### Reproduction

Restore existing inputs following [the benchmark guide](BENCHMARKS.md), [Juliet/SARD guide](JULIET-SARD.md) and [CVE guide](CVE-FIX-CORPUS.md). Use identical input paths and separate phase outputs:

```console
node scripts/score-dotnet-juliet.js INPUTS/juliet-csharp-1.3 OUT/csharp
node bin/kayfabe.js benchmark owasp-java INPUTS/owasp-java --out OUT/owasp-java
node bin/kayfabe.js benchmark juliet-java INPUTS/juliet-java-1.3/Java --out OUT/juliet-java
node bin/kayfabe.js benchmark sard INPUTS/sard-115 --out OUT/sard
node bin/kayfabe.js benchmark cve-fixes INPUTS/cve-downloaded --out OUT/cve-fixes
node scripts/score-supplied-apps.js INPUTS/supplied-apps OUT/supplied.json
node scripts/score-supplied-apps.js INPUTS/additional-dotnet-apps OUT/dotnet-apps.json
node scripts/compare-dotnet-accuracy.js BEFORE AFTER comparison.json 097b27acae6ff1eeed79ed5f11a7645de6d3dbdf d76d6f14fda4f12016ab61e59fc61a6225f06004
```
