# Where Kayfabe is useful

Assessment date: 2026-10-24. Use Kayfabe as an additional static review tool with human triage. The current evidence does not support using it as the only .NET security gate.

## What the measurements say

The final console-logging precision rerun preserved the established results below. The separate development-app warning reduction and exact provenance are recorded in [the precision report](CSHARP-CONSOLE-AUTH-PRECISION.md). Keep these datasets separate; they measure different things.

| Dataset | True positives | False positives | True negatives | Misses | Interpretation |
|---|---:|---:|---:|---:|---|
| Juliet C# 1.3 | 1,036 | 470 | 29,131 | 28,645 | Third-party synthetic cases; 3.49% overall recall, 1.59% false-positive rate |
| Earlier supplied .NET applications | 32 | 1 | 90 | 107 | Previously inspected development labels; 23.02% recall, 1.10% false-positive rate |
| Earlier frozen C# applications, each profile | 2 | 0 | 20 | 8 | Exposed development set; 20% recall |
| New safe-only C# set, each profile | — | 0 | 20 | — | Measures safe cases only; recall cannot be calculated |

Full Juliet C# recall includes unsupported weakness families. Within the two detected families, command-injection recall is 97.37% with a 52.63% false-positive rate; SQL-injection recall is 64.91% with a 26.32% false-positive rate. The low aggregate false-positive rate must not hide that noise. These are synthetic benchmark rates, not estimates of production performance.

There has been measurable precision progress: the [earlier frozen Juliet C# baseline](benchmarks/dotnet-juliet-phase2-baseline.json) recorded 1,036 false positives and 1,036 true positives. On the same input, label and unit-manifest hashes, the current baseline has 470 false positives and the same 1,036 true positives: 566 fewer false positives, a 54.63% reduction. Precision rose from 50.00% to 68.79%; overall recall stayed at 3.49%. These are historical improvements, not gains from this console-logging change.

The original real-CVE corpus still scores **0/8 parent/fix pairs**. The separate localized scoring policy scores 1/8 and must not replace the original number. Native C is unsupported; an empty C scan earns no true-negative credit. None of the supplied application results is a fresh independent holdout.

The corpus selftest is regression coverage written alongside the rules. Its passing score does not measure independent detection accuracy. See [benchmark methodology](BENCHMARKS.md), [the previous frozen aggregate](benchmarks/mvc-constant-sql-results.json), and [the .NET evaluation policy](benchmarks/dotnet-evaluation-policy.md).

## Comparison with established tools

There is no controlled head-to-head run against another scanner on these exact frozen inputs, options, rule versions and scoring policies. A numeric accuracy ranking would be unsupported.

| Tool | Documented C# analysis | What this comparison establishes |
|---|---|---|
| Kayfabe | Pattern rules, selected bounded value proofs, optional bounded project analysis | Local measurements above establish current coverage and limitations |
| CodeQL | Local/global data flow and taint tracking | A broader documented analysis model; no comparative score measured here |
| Semgrep Code | Cross-file and cross-function analysis | A broader documented analysis model; no comparative score measured here |
| Semgrep Community Edition | Single-function taint, single-file cross-function constant propagation | A different scope from Semgrep Code; no comparative score measured here |

Sources checked on the assessment date: [CodeQL C# data flow](https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-csharp/), [Semgrep C# support and edition differences](https://docs.semgrep.dev/languages/csharp). The descriptions are documented capabilities, not evidence that those tools detect every vulnerability.

## Practical recommendation

Kayfabe is worth using when its offline operation, no-install scanner, redacted reports and evidence-backed triage fit a review workflow. Treat findings as candidates and inspect them. Keep another established analyzer, dependency checks and human authorization/business-logic review in the workflow. A clean Kayfabe report cannot justify releasing an otherwise unreviewed application.

For .NET, the next meaningful gains require better ownership and call resolution, cross-file flows and broader vulnerability-family coverage. Continue narrowly checked false-positive fixes, but judge progress on both preserved detections and reduced misses. A future comparison should pin competing scanner versions/rules, use identical inputs and CWE matching, and report per-family recall, false-positive rates, unsupported coverage and runtime separately.
