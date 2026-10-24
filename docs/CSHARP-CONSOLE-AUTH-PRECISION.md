# C# console authentication logging precision

## Result

One distinct C# false positive was removed in both default and project-analysis profiles. In the nine previously inspected development apps, raw candidates changed from 35 to 34 per profile; adjudicated false positives changed from 11 to 10. Every other finding was retained, including all 18 previously adjudicated true positives and two additional SQL candidates preserved for separate review. The affected app's two Java warnings remain.

This change recognizes visible C# `Console.WriteLine` authentication outcome calls. The prior PROJ-LOGGING-001 heuristic did not recognize that spelling and incorrectly reported absent logging despite visible success and failure messages. This refines a low-confidence missing-evidence check; it does not establish that logs are collected, retained, monitored, or safe to expose.

The seven established benchmark scores are reported in the accompanying aggregate. No improvement in .NET recall is claimed. The affected application is outside those seven labeled suites.

Baseline and final counts are identical for every unit in these suites:

| Dataset | Units | TP | FP | TN | FN |
|---|---:|---:|---:|---:|---:|
| Juliet C# 1.3 | 59,282 | 1,036 | 470 | 29,131 | 28,645 |
| OWASP Java 1.2 | 2,740 | 571 | 289 | 1,036 | 844 |
| Juliet Java 1.3 | 57,649 | 2,410 | 1,172 | 27,596 | 26,471 |
| SARD PHP 115 | 20 | 10 | 0 | 0 | 10 |
| Original CVE snapshots | 16 | 1 | 1 | 7 | 7 |
| Earlier supplied apps | 227 | 87 | 11 | 79 | 50 |
| Earlier .NET apps | 230 | 32 | 1 | 90 | 107 |

The original CVE parent/fix score remains 0/8 pairs; the separately labeled localized policy remains 1/8. Zero SARD false positives has no false-positive-rate denominator because that set has no negative units. The C# scan took 112,721 ms before and 110,326 ms after (0.979×, within the 1.5× gate); these single shared-machine runs do not establish a speedup.

## Boundaries

The extractor uses a bounded syntactic subset. It requires both unambiguous outcome messages and a visible outcome on every modeled normal exit of each supported named authentication method. Explicit returns terminate paths. Predicates admit Boolean parameters and string/null comparisons on parameter-derived reads, combined with parentheses, negation, AND and OR.

Unsupported control flow, unknown authentication members, missing outcomes, ambiguous message text, source-visible aliases or custom Console owners, incomplete context and source budgets retain the original warning. Unicode formatting characters and unsupported identifier tokens also retain it. Ownership checks use a per-context cache.

Runtime feasibility of compound predicates, arbitrary helper semantics, exception behavior and external sink operation remain outside this heuristic. No general authentication-logging completeness claim follows from a suppressed candidate. Legacy logging-string limitations are unchanged.

The remaining Razor safe label was checked rather than accepted as proof. Earlier unencoded output can change browser context, so this pass leaves the warning in place. The remaining custom audit-helper warning also needs stronger ownership and call evidence. Juliet command cases need trustworthy String binding; SQL helper cases need safe cross-file caller resolution. Broad name-based suppressions would risk losing detections.

## Verification and reviews

- All seven established suites rerun against frozen main and the final implementation, with unchanged inputs, scoring policies, labels and options. Exact unit transitions and evaluator identities are checked.
- Safe-only C# set: 0 FP / 20 TN in each profile; recall undefined. All 67 frozen files and archive hashes verified. Twelve native C cases remain unsupported.
- Earlier frozen C# set: 2 TP / 8 FN / 0 FP / 20 TN in each profile; raw findings unchanged. Its 18 C cases remain unsupported. FinSuite remains at zero raw candidates per profile; that is not a security assurance.
- Full Windows regression suite: 515 tests, 512 passed, zero failed, three explicit platform skips. All 192 paired regression cases pass. These are self-authored regressions, not independent accuracy evidence.
- All 190 prior adversarial fixture comparisons unchanged. Fresh review probes cover escaped and Unicode owner shadows, cross-file aliases, omitted methods/properties/delegates, dead literal predicates, labels and mixed outcome messages.
- Two fresh review passes completed. Their material findings were fixed and independently rechecked. The v2 measurement candidate was retired after the final Unicode ownership finding; final evidence uses v3 only.
- User app code was never executed; dependencies were not installed. Published evidence contains sanitized aggregates and scanner-owned regression examples only.

Frozen baseline: `4c79e3ccb5861744c5391ce210b1bb2336edb753`. Final measured implementation: `4dc4774ef51943c8ead47fe83caa6c8fa9002dab`. Scanner byte hashes, archive/inventory hashes, exact totals and the timing gate are in [the aggregate](benchmarks/csharp-console-auth-precision-results.json). Measurements and full tests use the archived scanner. Its files match committed blobs with only verified UTF-8 CRLF-to-LF normalization where needed; the aggregate identifies the actual archive bytes. Working checkouts with different line endings can have different byte hashes. Documentation commits after the measured implementation do not change committed scanner or scorer blobs.

## Overall assessment

See [current limits and comparison](STATUS-AND-COMPARISON.md). Kayfabe has reduced historical Juliet C# false positives by 54.63% while preserving that baseline's true positives. Its overall C# recall is still 3.49%, and the original real-CVE score remains 0/8 pairs. Use it as an additional offline review tool with human triage and an established analyzer. A controlled head-to-head comparison has not been run.
