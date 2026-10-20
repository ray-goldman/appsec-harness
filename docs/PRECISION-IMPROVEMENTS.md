# Precision improvements

This change targets two causes of noise: Java injection warnings for provably
constant local values, and PHP code-evaluation warnings that previously claimed
attacker control without source evidence. The original benchmark inputs and
baseline JSON files remain unchanged.

## Measured results

All four final runs used the same input hashes as their original baselines and
harness source SHA-256
`421949170f87438e2a6df8608c04082afef3894f690c97abafd8d1b49d2bfc85`.
Measured October 20, 2026, with Node v24.16.0 on Windows.

| Dataset / policy | TP before → after | FP before → after | FPR before → after | Precision before → after |
|---|---:|---:|---:|---:|
| Juliet Java 1.3, 57,649 units | 2,410 → 2,410 | 2,342 → 1,504 | 8.14% → 5.23% | 50.72% → 61.57% |
| OWASP Java 1.2, 2,740 cases | 571 → 571 | 314 → 314 | 23.70% → 23.70% | 64.52% → 64.52% |
| SARD 115, 20 vulnerable locations | 10 → 10 | 0 → 0 | undefined → undefined | 100% → 100%* |
| CVE historical file+CWE, 16 snapshots | 1 → 1 | 1 → 1 | 12.50% → 12.50% | 50% → 50% |

Juliet has **838 fewer false positives (35.78%)**, with no lost true-positive
cases and no new false-positive cases. All 57,649 units were compared by ID.
Recall remains 8.34%; this work improves precision, not the large recall gap.

| Juliet CWE | FP before → after | Removed |
|---|---:|---:|
| SQL injection, CWE-89 | 1,820 → 1,208 | 612 |
| Command injection, CWE-78 | 444 → 252 | 192 |
| Open redirect, CWE-601 | 44 → 10 | 34 |

The CVE historical score remains **0/8 complete pairs**. The new, separate
localized score is **1/8**: PHPUnit has an evidenced parent finding and only a
review warning on the fix. Its localized counts are TP=1, FP=0, TN=8, FN=7.
The seven other parents remain missed. This is not an increase under the old
scoring policy.

*SARD 115 has no safe labels. Its precision cannot support a false-positive
claim, and its FPR is undefined.*

The [comparison JSON](benchmarks/precision-comparison.json) includes every
corrected Juliet case ID, all outcome transitions, per-CWE counts and hashes.
Current aggregates: [Juliet](benchmarks/juliet-java-1.3-precision.json),
[OWASP](benchmarks/owasp-java-1.2-precision.json),
[SARD](benchmarks/sard-115-precision.json) and
[CVE](benchmarks/cve-fixes-precision.json). Original `*-baseline.json` files
are untouched.

Reproduce against the previously downloaded datasets:

```sh
node bin/appsec.js benchmark owasp-java appsec-out/benchmarks/owasp-java --out appsec-reports/benchmarks/precision-owasp
node bin/appsec.js benchmark juliet-java appsec-out/benchmarks/juliet-java-1.3/Java --out appsec-reports/benchmarks/precision-juliet
node bin/appsec.js benchmark sard appsec-out/benchmarks/sard-115 --out appsec-reports/benchmarks/precision-sard
node bin/appsec.js benchmark cve-fixes appsec-out/cve-downloaded --out appsec-reports/benchmarks/precision-cve
```

## Detection changes

For Java SQL, command and redirect sinks, a bounded local analysis can prove
String literals, aliases, concatenations and constant split-array elements
independent of request data. It checks every assignment in the method, including
later loop writes. Fields, nested-block declarations, unknown calls, escaped or
mutated arrays, Unicode escapes, text blocks and lambdas do not qualify for this
suppression. It examines every matching sink in a line window. Proof work is
capped at 512 expression visits, 64 local variables and 50,000 characters per
method; exceeding a limit retains the warning.

The analysis is deliberately incomplete. It does not establish that an
application is secure or replace Java parsing, a call graph or path-sensitive
taint analysis. Kotlin retains its existing behavior.

`PHP-CODE-001` now distinguishes observed request-to-code flow from unresolved
dynamic execution:

- A recognized request source reaching an execution argument produces a high
  confidence, critical finding with `kind: "vulnerability"` and source-line evidence.
- Unknown values, including standard input and shell-command output, remain
  visible as low confidence, low severity `kind: "review"` findings.
- Constant code and supported numeric/boolean transformations do not establish
  attacker-controlled executable text.

PHP tracking covers local assignments, aliases, selected transformations,
indexed writes and bounded loop convergence. It does not resolve arbitrary helper
returns or cross-file calls. Review findings still require human assessment;
low severity is an uncertainty classification, not proof that the operation
is safe.

## CVE scoring

The original file-plus-CWE score is retained, including review warnings.
The separate [localized policy](CVE-LOCALIZATION.md) requires an open
vulnerability finding inside a reviewed source region, the exact advisory CWE
and the permitted evidence. Both revisions of all eight CVEs remain in the
denominator.

For PHPUnit, the parent reads the HTTP request body while the fix reads standard
input. The new detector records that distinction. The fixed revision still
receives a review warning because the safety of standard input depends on its
caller. A difference between the original and localized scores is a policy
difference; it must not be presented as a gain under the original policy.

## Review and remaining work

Two independent review passes followed the initial implementation. The first
exposed Java block-shadowing errors and PHP conditional, loop and array-write
flows that would have hidden real input. Regression tests cover those cases,
declaration order, safe array siblings and unresolved shell output.

The second review found exponential Java alias expansion, PHP input that only
reaches a sink on a third loop iteration, and namespaced functions incorrectly
treated as PHP numeric builtins. Work limits, loop convergence with conservative
fallback, and qualified builtin checks address those cases. Source evidence and
review classification also survive SARIF and triage export; HTML and Markdown
show the PHP source name and line.

Verification: `npm test` passed 79 tests; `node bin/appsec.js selftest` passed
all 145 paired cases at 100% regression recall and precision. The second
reviewer's final focused rerun passed 43 tests. Windows denied creation of the
symlink fixture in one localization test, so that subcheck was skipped; the
source-tampering check in the same test passed.

The tests added alongside these changes are regression checks. Juliet, OWASP
and the eight CVE pairs are now development data: measurements on them do not
establish generalization to unseen applications. Further work needs held-out
projects and SARD suites with negative labels.

Remaining Java false positives include constants declared inside nested blocks
and values passed through helper methods. Supporting these safely requires
lexical scope and call-flow modeling. The new proof deliberately leaves such
cases visible after the first review exposed an unsafe shadowing assumption.

Juliet's CWE-327 examples can label `Cipher.getInstance("AES")` safe even
though SunJCE defaults to ECB for this transformation. The warning remains:
lowering the benchmark FP count is not a reason to hide this cryptographic
risk. See the [Oracle JCA reference](https://docs.oracle.com/en/java/javase/25/security/java-cryptography-architecture-jca-reference-guide.html).
