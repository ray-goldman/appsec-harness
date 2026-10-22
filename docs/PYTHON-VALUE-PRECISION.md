# Python SQL choices and literal template HTML

This pass refines Python SQL and Jinja raw-output findings when the scanner can establish a bounded set of string values. It adds no runtime dependencies and never imports or executes target Python.

## Local SQL maps

The supported shape is three consecutive logical statements in the same suite of a top-level, zero-argument function:

```python
choices = {"price": "price ASC", "size": "size DESC"}
order = choices.get(key, "price ASC")
query = f"SELECT * FROM listings ORDER BY {order}"
```

Both dictionary keys and values must be ordinary, unescaped string literals. The fallback must also be a literal. Dictionaries are mutable in Python; safety here comes from checking every indexed occurrence of the map and selected-value names, rather than treating the dictionary as an immutable type.

Map mutation, aliases, argument escape, rebinding, deletion, loop/context-manager targets, global/nonlocal bindings, unsupported reflection and related formatted-string references retain findings. The query's substitutions must be simple references to the selected value, with no conversion, format specification or additional expression. Query-variable uses must be direct arguments to recognized SQL execution methods; later assignment or escape prevents the proof.

The proof refines `PY-SQLI-001`, `PY-SQLI-002` and `PY-SQLI-003`. SQL assembly lines must contain only the supported assignment. Sink-line suppression additionally requires a complete single-line `cursor.execute(query)` shape, or the corresponding `executemany`/`executescript` method. Additional arguments, expressions, nested sinks and other statements on the line do not borrow that suppression. Other rules retain their behavior.

## Literal template values

The supported template profile has exactly one indexed Python source file, an unaliased standard Flask import, one `app = Flask(__name__)` construction and the default adjacent `templates/` folder. Calls must directly use `render_template` with a literal HTML filename and explicit keyword bindings. Every recognized caller for the template must supply a proven value for each raw-output variable being refined.

A keyword value can be a direct string literal or a local variable in a top-level, zero-argument function. A local variable needs a literal initialization at the function's outer indentation before the call, and every recognized write must be a simple literal assignment. All other occurrences must be admitted render-binding reads or keyword labels. This admits literal choices under conditions while rejecting request text, concatenation, augmented assignments, missing initialization, nested scopes and binding targets.

Only the exact `{{ variable | safe }}` shape is refined. Every raw-output expression on a reported line must qualify. Templates with rebinding, macros, includes, inheritance, unknown tags or autoescape blocks retain findings. Basic `if`/`elif`/`else` and `for` tags are admitted without calls; loop targets must not shadow the output variable.

Unrecognized renderer aliases, wildcard imports, Flask binding changes, arbitrary decorators, context processors, custom loaders and alternate streaming/template APIs disable the proof. The only admitted decorators are simple `@app.route("literal-path")` forms. Additional Python source files also retain findings, rather than assuming their effects on rendering are harmless.

These are lexical recognizers under ordinary Python, DB-API and Flask/Jinja semantics, not a complete Python parser or a proof about arbitrary external runtime rewriting, import hooks or third-party callbacks. They do not validate the full Python grammar. Unknown external behavior is outside the supported model; detected dynamic constructs keep warnings.

## Bounds and fallback

The existing script index must be complete: at most 2,000 source entries, 8 MiB of indexed input and 100,000 JavaScript string code units per raw script file. The reused tokenizer separately caps comment-stripped code at 200,000 UTF-8 bytes, 50,000 tokens and nesting depth 64.

The SQL proof caps local maps at 32 entries, formatted substitutions at 16, admitted map candidates at 64 per file and query uses at 64 per candidate. Template analysis caps recognized calls at 64, keyword arguments at 32 per call, checked bindings at 128 and suppression attempts at 128 per project. Template input is capped at 200,000 UTF-8 bytes, with at most 256 tags and 2,000 code units per tag.

Malformed or unsupported strings/brackets, explicit continuations, semicolons, non-ASCII code identifiers and budget exhaustion keep findings. Non-ASCII text in any formatted string also disables these value proofs: Python identifier normalization inside f-strings can otherwise hide a rebinding from an ASCII name check. Ordinary Unicode in non-formatted string literals remains supported.

## Regression evidence and review

All **337 tests pass**, and all **182 vulnerable/fixed corpus pairs** retain 100% regression precision and recall. These metrics cover self-authored expectations and are not independent accuracy evidence.

The two new pairs in the [regression comparison](benchmarks/python-value-regression-comparison.json) hold source bytes constant between baseline and after scans. The safe SQL pair loses two overlapping SQL candidates, while both candidates remain in the vulnerable sibling with a request-controlled fallback. The safe template pair loses its warning, while the request-controlled branch remains flagged. Exact file hashes, finding sites and engine hashes are recorded separately from standard benchmark totals.

Both source review passes completed after fixes:

- The first reviewer found wildcard imports and alternate Flask streaming callers that invalidated renderer identity/caller coverage. Both now disable the proof.
- The second reviewer found Unicode-normalized assignment targets hidden inside f-strings. SQL and template repros now retain their findings, and ordinary Unicode literal markup still qualifies.
- Additional adversarial checks cover same-line and nested SQL sinks, effectful arguments, mutable maps, aliases, unsafe defaults, alternate render bindings, template rebinding and resource limits.

Supplied application source, labels, findings and comparisons remain local. Public fixtures are invented regression examples. Development apps used for tuning are not an independent holdout; no complete app-level recall or false-positive-rate claim is made.

## Seven existing benchmark results

All seven suites were rerun for both engines and have **zero unit transitions**: no FP-to-TN, TP-to-FN, TN-to-FP or FN-to-TP changes. This pass does not improve those existing benchmark scores. The new paired regression cases demonstrate the supported corrections separately.

The [benchmark comparison](benchmarks/python-value-precision-comparison.json) records per-unit checks, canonical report hashes, source hashes and unchanged input/scoring identities.

| Dataset | Units | TP before -> after | FP before -> after |
|---|---:|---:|---:|
| Juliet C# 1.3 | 59,282 | 1,036 -> 1,036 | 470 -> 470 |
| OWASP Java 1.2 | 2,740 | 571 -> 571 | 289 -> 289 |
| Juliet Java 1.3 | 57,649 | 2,410 -> 2,410 | 1,172 -> 1,172 |
| SARD PHP suite 115 | 20 | 10 -> 10 | 0 -> 0 |
| CVE-fix snapshots, original policy | 16 | 1 -> 1 | 1 -> 1 |
| Supplied apps | 227 | 87 -> 87 | 11 -> 11 |
| Additional self-authored .NET apps | 230 | 32 -> 32 | 1 -> 1 |

The separately versioned localized CVE policy also has zero unit transitions. Pair success remains **0/8** original and **1/8** localized. Existing detection gaps, low full-suite C# recall and the Razor false positive remain. No new project-analysis claim is made.

C# scanner duration was 91.162s -> 98.752s (1.083x), within the existing 1.5x scan budget. Both timings are fresh single runs on a shared machine; they do not establish a robust performance estimate. Preparation and hashing add wall time outside scanner duration.

## Measurement protocol

The baseline is merged main `9d30fabeeed44e6a94293460b0a497cac15cfeb9`, freshly measured from a separate Git archive with scanner byte hash `2e76b1f1dd07ff22cccff0dc07ab7ac0febcfb39cd0e246e45a97747b49b21de`. No previous benchmark timing was reused.

The frozen implementation is `268ab3a6c822e80d41a63e35f1197edeb0b60b58`, with measured scanner byte hash `84f9b352ef3691cfa69ac6de9a3e866cfe044df89621215d9b68dc289237ac69`. Documentation is committed separately. Source hashes identify exact measured bytes, including line endings. Benchmark/scoring source and policies are unchanged.

Inputs, labels, units, policies, options and evaluator identities must match before results are compared. Separate evaluator hashes are checked where recorded; the CLI evaluator files are also verified unchanged between commits. Per-unit transition checks and canonical raw-report hashes are recorded in the comparison artifact; mixed engine hashes are rejected.

Dataset tiers remain separate: previously seen Juliet/OWASP synthetic development data, upstream CVE source snapshots under the original and localized policies, and self-authored labeled apps. SARD has no safe denominator, so its false-positive rate is unmeasured. Unmatched app findings remain unclassified. No pooled or independent accuracy claim is made.

### Reproduction

Restore the existing inputs using [BENCHMARKS.md](BENCHMARKS.md), [JULIET-SARD.md](JULIET-SARD.md) and [CVE-FIX-CORPUS.md](CVE-FIX-CORPUS.md). Run each command for both engines with separate output folders:

```console
node scripts/score-dotnet-juliet.js INPUTS/juliet-csharp-1.3 OUT/csharp
node bin/kayfabe.js benchmark owasp-java INPUTS/owasp-java --out OUT/owasp-java
node bin/kayfabe.js benchmark juliet-java INPUTS/juliet-java-1.3/Java --out OUT/juliet-java
node bin/kayfabe.js benchmark sard INPUTS/sard-115 --out OUT/sard
node bin/kayfabe.js benchmark cve-fixes INPUTS/cve-downloaded --out OUT/cve-fixes
node scripts/score-supplied-apps.js INPUTS/supplied-apps OUT/supplied.json
node scripts/score-supplied-apps.js INPUTS/additional-dotnet-apps OUT/dotnet-apps.json
node scripts/compare-dotnet-accuracy.js BEFORE AFTER comparison.json 9d30fabeeed44e6a94293460b0a497cac15cfeb9 268ab3a6c822e80d41a63e35f1197edeb0b60b58
```
