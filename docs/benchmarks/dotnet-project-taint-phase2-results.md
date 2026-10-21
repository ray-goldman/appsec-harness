# .NET project taint Phase 2 measurement

Measured 2026-10-21 on Juliet C# 1.3, a seen third-party synthetic dataset. This is development evidence, not an independent application-accuracy estimate.

## Default scanner baseline

| Units | TP | FP | TN | FN | Recall | False-positive rate | Precision |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 59,282 | 1,036 | 1,036 | 28,565 | 28,645 | 3.49% | 3.50% | 50.00% |

The baseline used the complete Juliet input and label set. C# parser coverage was 46,597/46,597 eligible files and 173,779/173,779 discovered methods. Input SHA-256: `6fde14e0e66fbd5fa2f6a58dae4299e6d92f6951b74b9a8ce9b061be5f515c9b`. Label SHA-256: `dfae8f9c30ba7c001c5ef2a2c6bd807ed477d48b42de1063b5f1eb5e09b6d77a`. Harness source SHA-256: `f1bc0cc8d5491eb6ef987c89bbf4e298879d7e4f7eafe98f605ef63c12040d48`.

## Project-analysis measurement

The opt-in run was stopped after approximately 15 minutes without a report. The bounded runner configuration was 8 fixpoint iterations and 10,000 call edges; the project index also has a 50,000-method cap. No experimental TP/FP totals were produced. The cross-file Juliet recall gate (60%) is **not measured** and must not be inferred from the default baseline.

The runner records these budgets and marks any produced result as diagnostic-only when project analysis is truncated. It does not treat an incomplete project graph as a passing phase score.

## Other benchmark inputs

Only `appsec-out/benchmarks/juliet-csharp-1.3` is present in this worktree. OWASP Java, Juliet Java, SARD-115, CVE-fix pairs, WebGoat.NET, eShop, and the supplied application benchmark inputs were not available here, so no refreshed scores are claimed for them. Archived JSON baselines are not reruns.

## Ship status

Project-wide .NET findings remain behind `--dotnet-project-analysis`. Juliet is seen development data, the experimental accuracy gate was not measured, and the independent-app and public-repository gates remain unmeasured. Do not enable this analysis by default based on these results.
