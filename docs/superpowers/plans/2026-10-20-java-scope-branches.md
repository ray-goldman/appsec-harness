# Java scope and constant branches

Approved scope: improve Java false positives through lexical scope handling,
then bounded constant-branch evaluation. Rerun all four independent datasets
and complete two review-and-improve passes before opening a PR.

Base: `84d3fc116349a1f2149ba85cb02833e39b5bdf73`, the tip of PR #3.
The new PR targets that branch while #3 remains open.

## Implementation order

1. Bind local declarations, references and writes to lexical blocks. Permit
   nested constants and disjoint sibling declarations; preserve uncertainty
   about fields, declarations not yet in scope and unsupported syntax.
2. Evaluate a bounded subset of constant Java conditions without executing
   target code. Exclude an assignment only when its branch is provably
   unreachable. Unknown conditions preserve all paths. Cover both safe
   examples and unsafe look-alikes.
3. Review correctness and missed detections; fix findings with regressions.
4. Review generalization, Java semantic edge cases and resource bounds;
   fix findings and verify the corrections.
5. Freeze scanner sources. Run unit tests, paired selftests, OWASP Java,
   Juliet Java, SARD 115 and the pinned CVE corpus. Compare case outcomes
   with the previous precision measurements.
6. Document exact deltas, source/input hashes, limits and both reviews.
   Open a PR only after the reviews and measurements are complete.

## Acceptance

- Fewer false positives, no lost previously detected true-positive cases.
- Existing benchmark inputs, labels and scoring policies stay unchanged.
- Unknown syntax and exhausted analysis budgets retain warnings.
- Scope and branch proofs never execute source code or add runtime dependencies.
- Preserve regression cases; new rule behavior has paired corpus fixtures.
- No automatic merge.

## Execution record

- Started from a clean checkout on `codex/java-scope-branches`.
- Scope implementation delegated; branch implementation follows it.
- Scope implementation completed: lexical binding identities, nested blocks,
  disjoint sibling declarations and assignment-position resolution. Unsupported
  header declarations retain warnings.
- Interim independent scope review found no actionable issue. It ran 20 Java
  test groups and ten additional scope/mutation probes. Full suite: 87 tests;
  paired corpus: 146 cases.
- Constant-branch implementation started. SQL assignment and sink findings
  must both honor the proof to avoid leaving duplicate safe-code alerts.
- Constant-branch implementation completed with typed, bounded expressions,
  `if/else`, ternaries and conservative switch traversal. Unknown conditions
  keep every assignment. Conditions include all syntactic writes, including
  later loop writes, to prevent circular reachability proofs.
- First full review found three unsafe suppression paths: mixed char/int
  ternary promotion, parenthesized mutations, and array escapes hidden by the
  initial mutation fix. All were reproduced and fixed with regression tests.
  The reviewer independently passed 33 Java precision groups, 15 expression
  probes and four statement-boundary probes, with no unresolved findings.
- Independent adversarial tests cover integer semantics, String identity,
  changed loop guards, switch fallthrough, nested breaks, dangling else,
  mixed SQL fragments and non-benchmark constants.
- Fresh full verification after first review: 110 tests and all 147 corpus
  pairs passed. A fresh reviewer is performing the second full pass.
- Second broad review completed with two findings: array element writes hidden
  by parentheses/nested indices, and Java Unicode preprocessing hidden from
  the proof by repeated `u` escapes or comment stripping. Fifteen additional
  adversarial probes found no other issue. Both findings are in one fix wave,
  followed by scoped independent verification before measurements.
- The fix wave added balanced array-access scanning and a raw-source Unicode
  guard. The second reviewer approved both fixes after 15 independent probes,
  113/113 tests and 147/147 corpus pairs. No unresolved findings remain.
- Root independently reran the full tests and corpus with the same counts.
  Scanner source hash frozen at
  `3f3f4563f3b22e75e0951233d2548eeb61a703e326086e336dc4e03a5d0af60f`.
  All four official benchmark reruns started after the final review approval.
- All four runs completed with the frozen source hash and unchanged inputs,
  labels and policies. Juliet FP: 1,504 → 1,226; OWASP FP: 314 → 301.
  SARD and both CVE policies are unchanged. Every scored unit was compared:
  zero lost true positives and zero new false positives.
- Added new aggregate reports, per-case transition evidence and the
  `JAVA-SCOPE-BRANCHES.md` results/review/limitations record. Original baselines
  and previous precision reports remain untouched.
