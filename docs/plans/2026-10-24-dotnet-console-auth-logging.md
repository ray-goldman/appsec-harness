# C# console authentication logging precision

## Scope

Refine PROJ-LOGGING-001, a low-confidence missing-evidence heuristic. A supplied C# server visibly writes authentication success and failure messages to Console.WriteLine, but the rule does not recognize that spelling. This is development data already inspected; it is not an independent evaluation.

Recognize bounded, syntactically visible console outcome calls inside named authentication methods. Require both success and failure messages and a logged outcome on every supported normal control-flow exit. Keep warnings for unsupported syntax, ambiguous ownership, missing outcomes, unreachable calls, startup-only logging, data strings and comments. Do not claim that console output is collected, retained, monitored or sufficient for a security audit.

Supported predicates are Boolean parameters and string/null equality checks on parameter-derived reads, combined with parentheses, negation, AND and OR. This models syntactic paths; it does not prove runtime feasibility, solve compound contradictions, or establish arbitrary helper-call semantics. Every modeled normal exit still needs visible logging, including exits in overapproximated branches. Numeric predicates, local Boolean flags, labels, loops, exception handling, lambdas inside authentication methods, ambiguous mixed-outcome messages and omitted authentication members retain the warning. Explicit returns terminate paths so later unreachable statements cannot supply logging. Binding checks use bounded complete source context and cache the context result. Source budgets retain the original heuristic when exceeded.

The existing Razor warning remains: earlier raw output can alter browser context. Do not change frozen labels or suppress it based on the label alone.

## Execution and gates

1. Freeze main 4c79e3ccb5861744c5391ce210b1bb2336edb753. Add failing scanner-owned safe/unsafe regression tests, then implement bounded evidence extraction and a paired corpus case.
2. Run a fresh review of implementation and adversarial cases; fix substantive findings.
3. Freeze implementation and rerun all seven established suites, the 20-case safe C# set, earlier frozen applications and FinSuite with unchanged inputs, keys, options and scorers. Preserve every previous true-positive unit and avoid new false positives. Compare raw supplied-app findings as well as benchmark units. Record hashes and exact changes; require 100% paired-corpus regression results and the full test suite.
4. Run a fresh second review of code and final evidence. Publish only scanner-owned fixtures and sanitized aggregate results. Open a PR after both reviews; do not merge it.

Accept a small verified reduction over a broader suppression. Report zero benchmark movement honestly if the affected real app is outside the labeled suites. External product comparisons describe documented capabilities, not measured accuracy rankings.
