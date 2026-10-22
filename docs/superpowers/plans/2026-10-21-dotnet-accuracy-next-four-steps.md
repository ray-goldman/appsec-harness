# .NET Accuracy: Next Four Steps

**Goal:** Reduce incorrect .NET alerts and improve detection of supported vulnerabilities, while keeping scans practical to run.

**Architecture:** Extend the existing bounded C# parser, constant proofs and versioned project summaries. Unknown syntax, unresolved calls and incomplete graphs must retain conservative findings and expose diagnostics. No installed runtime dependencies.

**Tech stack:** Node.js 20 or newer; JavaScript scanner; existing native C# lexer, parser and summary engine.

**Spec:** [Approved .NET design](../specs/2026-10-20-dotnet-taint-and-evaluation.md). This is a four-step delivery roadmap within that design, rather than a replacement for its gates.

## Constraints and starting point

The merged constant-sink pass scored 1,036 TP, 560 FP, 29,041 TN and 28,645 FN on 59,282 Juliet C# units: 3.49% recall, 1.89% FPR and 64.91% precision. The 560 FPs consist of 200 command-injection and 360 SQL-injection units. Juliet is seen third-party synthetic development data. Its overall score includes unsupported CWEs; report supported-CWE and cross-file subsets separately, preserving the full denominator.

The last project-analysis benchmark stopped after approximately 15 minutes without a completed report. Its accuracy and runtime gates are unmeasured. Existing parser completeness counts do not establish grammar correctness. Independent-app and adjudicated public-repository gates also remain unmeasured.

Every changed rule needs a vulnerable/safe corpus pair. Secrets remain redacted, target code is read statically, and benchmarks run offline. Preserve historical reports and dataset tiers. Keep experimental project findings opt-in until the approved gates pass.

## Review focus

- Reassignments, escaping aliases and branch-dependent writes must invalidate a constant proof.
- A helper name or sanitizer spelling cannot establish safety; model its actual behavior for the sink category.
- Public/protected entry points and unresolved callers cannot be suppressed because visible callers happen to use constants.
- Ambiguous overloads, DI registrations and incomplete project graphs must not manufacture certainty.
- Parser fallback, graph truncation and missing datasets must remain visible in every report.

## 1. Restore measurement and classify the remaining failures

**Work:** Recover and verify the pinned inputs for Juliet C#, OWASP Java, Juliet Java, SARD, CVE-fix pairs and supplied apps. Reproduce a merged-main baseline with frozen labels, scoring policy and SHA-256 manifests. Group the 560 C# FPs by actual cause: helper return, field/alias, control flow, caller ownership or unsupported expression. Separately inspect misses in currently supported CWEs before considering new categories. Deduplicate related variants to avoid ranking a repeated synthetic idiom as many distinct causes.

**Files:** `scripts/score-dotnet-juliet.js`, `scripts/compare-dotnet-constant-sinks.js`, `docs/benchmarks/`, `docs/DOTNET-CONSTANT-SINKS.md`.

**Deliverable/gate:** Reproducible per-unit baseline, prioritized root-cause table and runtime profile. Any unavailable input is explicitly unmeasured. Freeze all acceptance criteria before tuning.

## 2. Extend proofs through safe helpers and control flow

**Work:** Start with the largest verified FP group from step 1. Extend constant/value summaries through uniquely resolved helpers and immutable local aliases, then handle branch-local writes and effective sanitizers. Suppress only when the value reaching the specific sink is proved safe on every relevant path. HTML encoding provides no SQL or command-injection safety. Mutation, unknown calls, unsupported syntax and uncertain control flow retain warnings.

**Files:** `src/csharp-constant-sinks.js`, `src/parsers/csharp/`, `src/dotnet/method-summaries.js`, corresponding tests and corpus pairs.

**Deliverable/gate:** Same-unit comparison with fewer than 560 FPs, all 1,036 existing TPs retained, and zero newly flagged safe units. Proposed planning target: at least 25% fewer FPs (420 or fewer); report the actual result even if this target is missed. Add adversarial tests for all safety assumptions, including mutation and unsafe caller twins.

## 3. Make cross-file analysis complete and useful

**Work:** Profile the stalled project run before expanding propagation. Reuse parsed files and summaries, index candidate call targets, and avoid recomputing unchanged summaries. Partition analysis only along sound project/assembly boundaries and retain visible unresolved edges. Then improve propagation through local aliases, controller/service/repository calls and uniquely resolved DI implementations. Emit source/sink paths with high confidence for visible tainted callers; preserve low confidence for unknown public entry points. Apply constant-caller suppression only under the approved visibility and caller-completeness rules.

**Files:** `src/dotnet/project-index.js`, `call-resolution.js`, `method-summaries.js`, `summary-fixpoint.js`, `analysis.js`, `project.js`, and corresponding integration tests.

**Deliverable/gate:** Complete the full benchmark within a declared, frozen runtime and memory budget, reporting limits and unresolved calls. Target the approved 60% recall gate on the frozen Juliet cross-file subset, with no increase in FPs on the same labeled units. Report overall recall separately. A truncated run cannot pass; missed accuracy gates keep the feature opt-in. Measure default-scan time separately against the approved 1.5x budget.

## 4. Validate on applications, review twice and publish evidence

**Work:** Rerun every restored benchmark and compare decisions by unit, CWE and confidence. Adjudicate seen WebGoat.NET findings and missed known vulnerabilities. Follow the approved protocol for a frozen 30-50 repository sample and approximately 150 findings reviewed by two adjudicators. Arrange an isolated independent author using only the feature brief; if unavailable, retain that gate as unmeasured. Score the independent set once at its phase boundary and retire it after results inform changes.

**Review passes:** First, examine correctness and adversarial bypasses of every suppression. Second, examine benchmark provenance, label consistency, regressions, report claims and runtime/truncation behavior. Resolve findings and rerun affected checks before opening the PR.

**Deliverable/gate:** `npm test` and CLI selftest pass; all available benchmark results and missing measurements are documented. Apply the approved zero-FP development-app gate and public-sample precision gate (95% lower confidence bound at least 80%) with a documented stratified estimation method. Distinguish development gains from independent accuracy. Publish the PR with before/after counts, remaining gaps and default/opt-in status.

## Execution

Implement natively, preserving the user's earlier execution preference. Deliver each step as a reviewable change; use the executing-plans workflow for implementation. Execution was subsequently authorized; results and missed/unmeasured gates are recorded in [the execution report](../../DOTNET-ACCURACY-ROADMAP.md).
