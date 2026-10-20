# Java scope and constant branches

This change extends the local Java constant proof to nested lexical scopes and
provably constant branches. It affects SQL, command and redirect findings.
SQL assembly findings use the same proof as execution findings.

## Measured results

Compared with the previous [precision measurements](PRECISION-IMPROVEMENTS.md):

| Dataset / policy | TP before → after | FP before → after | FPR before → after | Precision before → after |
|---|---:|---:|---:|---:|
| Juliet Java 1.3, 57,649 units | 2,410 → 2,410 | 1,504 → 1,226 | 5.23% → 4.26% | 61.57% → 66.28% |
| OWASP Java 1.2, 2,740 cases | 571 → 571 | 314 → 301 | 23.70% → 22.72% | 64.52% → 65.48% |
| SARD 115, 20 vulnerable locations | 10 → 10 | 0 → 0 | undefined → undefined | 100% → 100%* |
| CVE historical file+CWE, 16 snapshots | 1 → 1 | 1 → 1 | 12.50% → 12.50% | 50% → 50% |

Juliet has **278 fewer false positives (18.48%)**; OWASP has **13 fewer
(4.14%)**. Every scored unit was compared by ID, including both revisions of
each CVE. There are **zero lost true-positive cases and zero new false-positive
cases** across all four datasets.

| Changed category | FP before → after |
|---|---:|
| Juliet SQL injection, CWE-89 | 1,208 → 956 |
| Juliet command injection, CWE-78 | 252 → 228 |
| Juliet open redirect, CWE-601 | 10 → 8 |
| OWASP SQL injection, CWE-89 | 129 → 116 |

Recall is unchanged: 8.34% for Juliet, 40.35% for OWASP and 50% for SARD.
Historical CVE scoring remains **0/8 complete pairs**. The separate localized
policy remains **1/8**, with TP=1, FP=0, TN=8 and FN=7. These two policies are
reported separately and have not changed.

*SARD has no safe labels, so its apparent precision cannot support a
false-positive claim.*

The [comparison JSON](benchmarks/java-scope-branches-comparison.json) records
all transitions, corrected case IDs, per-CWE counts and input hashes.
New aggregates: [Juliet](benchmarks/juliet-java-1.3-scope-branches.json),
[OWASP](benchmarks/owasp-java-1.2-scope-branches.json),
[SARD](benchmarks/sard-115-scope-branches.json) and
[CVE](benchmarks/cve-fixes-scope-branches.json). Original baselines and previous
precision reports remain unchanged.

All four runs used unchanged inputs, labels and scoring policies, with source
SHA-256 `3f3f4563f3b22e75e0951233d2548eeb61a703e326086e336dc4e03a5d0af60f`.
Measured October 20, 2026, using Node v24.16.0 on Windows. The recorded Juliet
scanner phase took 127.9 seconds, versus 107.6 seconds in the previous run;
these were not controlled performance measurements and exclude dataset
preparation and report generation.

Reproduce against the previously downloaded datasets:

```sh
node bin/appsec.js benchmark owasp-java appsec-out/benchmarks/owasp-java --out appsec-reports/benchmarks/scope-branches-owasp
node bin/appsec.js benchmark juliet-java appsec-out/benchmarks/juliet-java-1.3/Java --out appsec-reports/benchmarks/scope-branches-juliet
node bin/appsec.js benchmark sard appsec-out/benchmarks/sard-115 --out appsec-reports/benchmarks/scope-branches-sard
node bin/appsec.js benchmark cve-fixes appsec-out/cve-downloaded --out appsec-reports/benchmarks/scope-branches-cve
```

## Proof boundaries

Each declaration, reference and write resolves to its lexical binding. Constants
inside nested blocks and disjoint sibling declarations can qualify. Unsupported
header declarations, overlapping bindings and captured values retain warnings.

A typed expression reader handles bounded integer arithmetic, booleans,
characters, String concatenation and `charAt`. It can select constant `if/else`
and ternary arms. A limited switch traversal preserves fallthrough and only
models direct terminal breaks. Unknown conditions retain every path.

Guard facts must agree across every syntactic write, including writes in a
currently unreachable branch and writes after a sink. This prevents a proof
from assuming its own conclusion or missing a changed guard on a later loop
iteration. Exception handlers remain opaque and their writes still count.

Java semantics matter here: integer division truncates toward zero, String
equality compares references, and switch cases can fall through. Unsupported
numeric forms, overflow, String reference comparisons and mixed numeric ternary
types remain unknown. See the Oracle Java Language Specification for
[division](https://docs.oracle.com/javase/specs/jls/se25/html/jls-15.html#jls-15.17.2),
[reference equality](https://docs.oracle.com/javase/specs/jls/se25/html/jls-15.html#jls-15.21.3)
and [switch execution](https://docs.oracle.com/javase/specs/jls/se25/html/jls-14.html#jls-14.11.3).

Limits include 50,000 characters per method, 64 locals, 1,024 scopes, 4,000
characters and 1,024 tokens per expression, 512 evaluation steps, expression
depth 48, statement depth 64, 12,000 method tokens and 24,000 statement work
steps. Exhaustion preserves warnings. The harness never executes scanned code.

## Review record

The first independent review found three unsafe suppression paths: mixed
character/integer ternary promotion, parenthesized variable mutations, and an
array escape missed by the initial parentheses fix. Each has a regression test.
The reviewer then passed 33 Java precision groups, 15 expression probes and four
statement-boundary probes without an unresolved finding.

The second independent review found array writes hidden by parenthesized
elements or nested indices. A further probe confirmed that repeated `u`
characters in Unicode escapes could hide a mutation from the proof. Java
translates these escapes before recognizing comments; its
[Unicode escape grammar](https://docs.oracle.com/javase/specs/jls/se25/html/jls-3.html#jls-3.3)
allows more than one `u`.

The fixes use a balanced, bounded array-access reader and inspect raw source
for Unicode escapes before allowing a constant proof. Regression tests cover
both top-level and nested-block array mutations, ordinary safe reads, repeated
Unicode markers and Unicode newlines hidden in comments.

The second reviewer independently reran the original reproductions and 15
additional probes. Unsafe writes retained warnings; supported safe reads stayed
quiet. Both findings were resolved with no remaining actionable issue.

Fresh verification after these fixes passed **113 tests** and **147/147 paired
corpus cases**. Windows could not create the symlink fixture in one localization
subcheck; the source-tampering check in that test passed.

## Remaining gaps

This is a local proof over a restricted Java subset. Helper returns, cross-file
flows, general aliasing and unsupported control flow still need parsing and
call-flow analysis. The change does not add CVE-specific mechanisms or reduce
the broad recall gap.

Two remaining OWASP examples show where further work belongs:

- `BenchmarkTest00090` selects a constant command argument, but builds the
  command prefix through `Utils.getOSCommandString("echo")`. The unresolved
  helper result keeps the command warning.
- `BenchmarkTest00278` applies Spring `HtmlUtils.htmlEscape` before printing
  to the response. The XSS rule still flags it. Supporting that safe case
  requires a context-aware sanitizer model and unsafe controls.

Juliet's safe labels for `Cipher.getInstance("AES")` remain a known disagreement:
the warning is retained because the default transformation can use ECB.
SARD 115 has no negative labels and cannot measure false-positive performance.

These datasets have now informed implementation decisions. Results measure
progress on development data; held-out projects are still needed to assess
generalization. New regression fixtures demonstrate specific behaviors, not
production accuracy.
