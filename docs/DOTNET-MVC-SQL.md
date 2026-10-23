# MVC input reaching local EF SQL strings

`CS-SQLI-002` adds a bounded source-to-sink check for a previously missed shape:

```csharp
public IActionResult Search(string q) {
    if (string.IsNullOrEmpty(q)) return RedirectToAction("Index");
    string sql = $"SELECT * FROM Listings WHERE Name LIKE '%{q}%'";
    var rows = _db.Listings.FromSqlRaw(sql).ToList();
    return View(rows);
}
```

The existing inline SQL rule remains unchanged. The new rule requires visible MVC action ownership, a model-bound string parameter, a tracked string value and a constructor-bound field whose type resolves to a visible EF context with an ordinary `DbSet<T>` property. It does not treat every method parameter or API named `FromSqlRaw` as a source or sink.

## Supported model and limits

Controllers must be public, directly derive from `Controller` or `ControllerBase`, and have supported MVC/auth metadata. Actions must be public instance methods returning `IActionResult`, with simple `string`, `int` or `bool` parameters; only strings supply request taint. The admitted explicit binding attributes are `FromQuery`, `FromRoute`, `FromForm` and `FromHeader`.

The first SQL argument must be a tracked identifier, which can be the bound parameter itself. Values flow through simple local assignments, aliases, string concatenation and ordinary interpolated strings with identifier-only holes. Parameter and query reassignments kill earlier evidence. Constant SQL and parameterized `FromSql`/`FromSqlInterpolated` calls do not trigger this rule. Constant `FromSqlRaw` text with separate bound arguments also remains quiet.

Leading return guards admit source null/empty checks or simple zero-argument predicate calls, including the common authentication predicate shape. Predicate bodies are not proven: this is possible-flow evidence under ordinary MVC/EF semantics, not a proof of runtime reachability. Arbitrary input validators, unknown sanitizers and unsupported control flow decline the added detection. A declined analysis makes no claim that the method is safe.

The recognizer rejects conditional/short-circuit sink expressions, loops, lambdas, ref/out writes and unsupported assignment targets. It scans terminal return expressions before stopping, and preserves earlier findings when later unsupported writes stop sequential analysis. Literal constant guards cannot manufacture reachability. Visible custom framework/metadata types, API declarations, aliases, custom DbSet getters, ambiguous/partial types and unknown receiver ownership decline this rule.

Analysis requires complete scanner input and is capped at 1,000 C# source files, 8 MiB total source, 100,000 code units and 20,000 tokens per file, 512 indexed methods and 4,096 tokens per action body. Value expressions cap at 256 tokens, recursive evaluation at 16 levels and interpolation at 32 simple holes. Lexer errors, directives, unbalanced delimiters and unsupported non-ASCII code punctuation decline the added rule. Existing rules continue to run.

This is a lexical/structural recognizer, not Roslyn compilation or complete framework resolution. External custom model binding, application conventions, runtime rewriting and unseen framework extensions remain outside its model. Async actions, arbitrary helpers, service/repository flows and more complex expressions remain gaps.

## Regression evidence and reviews

All **344 tests pass** and all **184 vulnerable/fixed corpus pairs** retain 100% regression precision and recall. These self-authored cases measure regressions, not independent accuracy.

The two new [paired comparisons](benchmarks/mvc-sql-regression-comparison.json) use identical source bytes for before/after scans. Both vulnerable local-formatting cases move from no SQL candidate to one `CS-SQLI-002` candidate. Both idiomatically parameterized siblings remain quiet. The artifact records input hashes, engine hashes and finding sites separately from benchmark totals.

Both source review passes completed after fixes:

- Pass 1 found a whitespace-sensitive API-veto regex, unsupported writes, conditional/dead sinks, incorrect action ownership, shadowed metadata and skipped terminal-return sinks. The fixes replace the regex with token checks and tighten ownership, flow and write handling.
- Pass 2 found constant leading guards and explicit receiver/member writes. Tests now cover these cases, parsing budgets and preservation of earlier SQL evidence when a later member write stops analysis.

Local development-app rescans check the previously reviewed labels and newly resolved misses. Supplied source, target names, labels and findings remain local. Public examples are invented fixtures. No independent holdout or complete application recall claim is made.

## Measurement protocol

The baseline is merged main `cbecf6d5ba6579783063e5ef298d37301b867c98`, freshly measured from a separate Git archive. The frozen implementation is `33a0611f2c9a71769ce74128f8d03e25c4f75ded`. Documentation is committed separately. Exact measured byte hashes are recorded in the comparison artifacts; line endings are part of these hashes.

Benchmark/scoring source, input hashes, labels, options, policies and evaluator identities must match before comparison. Results retain separate dataset tiers: previously seen third-party synthetic suites, upstream CVE snapshots under original and localized policies, and self-authored labeled apps. Development results are not a blind evaluation. SARD has no safe denominator; its false-positive rate is unmeasured. Unmatched benchmark findings remain unclassified.

For reproduction, use the seven commands in [the previous measurement protocol](PYTHON-VALUE-PRECISION.md#reproduction), then run `scripts/compare-dotnet-accuracy.js` with the baseline and frozen commits above. No target application is built, imported or executed.

## Seven existing benchmark results

All seven suites have **zero unit transitions**: no lost true positives, new false positives, corrected false positives or recovered misses under their existing scoring policies. This pass does not improve these seven benchmark scores.

The [comparison artifact](benchmarks/mvc-sql-benchmark-comparison.json) checks matching input hashes, scoring identities and unit labels, records canonical raw-report hashes, and rejects mixed engine hashes.

| Dataset | Units | TP before -> after | FP before -> after |
|---|---:|---:|---:|
| Juliet C# 1.3 | 59,282 | 1,036 -> 1,036 | 470 -> 470 |
| OWASP Java 1.2 | 2,740 | 571 -> 571 | 289 -> 289 |
| Juliet Java 1.3 | 57,649 | 2,410 -> 2,410 | 1,172 -> 1,172 |
| SARD PHP suite 115 | 20 | 10 -> 10 | 0 -> 0 |
| CVE snapshots, original policy | 16 | 1 -> 1 | 1 -> 1 |
| Supplied labeled apps | 227 | 87 -> 87 | 11 -> 11 |
| Additional self-authored .NET apps | 230 | 32 -> 32 | 1 -> 1 |

The localized CVE policy is checked separately in the artifact. Original pair success is **0/8**; localized pair success is **1/8**.

Full-suite C# recall remains 3.49%, with 1.59% FPR. The existing Razor false positive and broader detection gaps remain. New regression fixtures are excluded from these totals.

C# scanner duration was 99.851s -> 95.790s (0.959x), within the existing 1.5x budget. Fresh single runs on a shared machine do not establish robust performance estimates; preparation/hashing time is additional.

Measured scanner byte hashes:

- Baseline: `d166c151c0a4f2f005db7d52bf16dcb66f94da0643b0a953837d142c075afdcf`.
- Frozen implementation: `895c25f38fbd06e8808cb4627d71d09be87796da2ba2da65e3bec339e2965e6a`.
