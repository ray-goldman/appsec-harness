# .NET constant SQL and command precision

This pass adds a bounded method-local constant proof before the existing C#
SQL-injection and command-injection findings are emitted. It addresses Juliet
C# safe twins where the sink receives only local literals, including platform
specific literal command prefixes. It does not treat helper names, sanitizer
names, parameters, or arbitrary method results as safe.

The proof accepts a sink expression only when every referenced local has one
unambiguous declaration and every syntactic write is itself a literal or a
composition of other proved constants. Unknown expressions, overloaded or
interpolated strings, helper calls, unknown writes, parser gaps, and ambiguous
locals retain the finding. A `Process.Start` overload with multiple arguments
also retains the finding because the existing regex can match a dynamic later
argument.

## Juliet C# results

The compared reports use the same Juliet C# 1.3 archive, 59,282 units, label
manifest, and scoring policy. Juliet is third-party synthetic code that has
been observed during development; these are not independent application
accuracy results.

| Measure | Before | After | Change |
|---|---:|---:|---:|
| TP | 1,036 | 1,036 | 0 |
| FP | 1,036 | 560 | −476 (−45.95%) |
| TN | 28,565 | 29,041 | +476 |
| FN | 28,645 | 28,645 | 0 |
| Recall | 3.49% | 3.49% | unchanged |
| False-positive rate | 3.50% | 1.89% | −1.61 percentage points |
| Precision | 50.00% | 64.91% | +14.91 percentage points |

| CWE | TP | FP before → after | FPR before → after |
|---|---:|---:|---:|
| CWE-78 command injection | 370 | 370 → 200 | 97.37% → 52.63% |
| CWE-89 SQL injection | 666 | 666 → 360 | 64.91% → 35.09% |

Every one of the 59,282 units was compared by ID: 476 FP→TN, zero TP→FN,
zero TN→FP, and zero FN→TP. The complete counts by CWE, changed unit IDs,
input hashes, and scanner source hashes are in the
[comparison artifact](benchmarks/dotnet-constant-sinks-comparison.json).

Both scans parsed all 46,597 eligible C# files and all 173,779 discovered
methods. The scanner-reported durations were 91.6 seconds before and 100.2
seconds after; these are uncontrolled end-to-end timings and do not establish
a performance regression. The proof currently reparses a file for each
matching sink, so caching per-file analysis is a candidate optimization.

## Remaining gaps

The proof does not follow helper returns, fields, deserialized values, or
cross-file aliases. Those safe-labeled cases remain warnings until the summary
engine can establish the source and value at the sink with confidence. The
large remaining Juliet false-positive counts and low recall mean this change
does not make broad claims about .NET accuracy. The separate OWASP Java,
Juliet Java, SARD, CVE-fix, and supplied-app datasets were not present in this
checkout, so they were not rerun here.

## Reproduction

```sh
node scripts/score-dotnet-juliet.js appsec-out/benchmarks/juliet-csharp-1.3 appsec-reports/benchmarks/fp-roadmap-baseline
node scripts/score-dotnet-juliet.js appsec-out/benchmarks/juliet-csharp-1.3 appsec-reports/benchmarks/fp-roadmap-final
node scripts/compare-dotnet-constant-sinks.js
```

The scan does not execute Juliet source code. The pairwise comparator aborts if
the input hashes, labels, or scoring policy change.
