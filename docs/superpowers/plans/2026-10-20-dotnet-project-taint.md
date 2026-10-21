# .NET Project-Wide Taint Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Propagate taint across supported C# methods and files through versioned summaries and conservative bounded call resolution.

**Architecture:** Consume the C# AST from the parser plan to build a project symbol index and per-method summaries. Resolve only calls whose target is sufficiently unambiguous, propagate summaries to a bounded fixpoint, and retain file-local regex behavior as fallback for unsupported files.

**Tech Stack:** Node.js plain JavaScript, built-in test runner, existing scanner/report modules; no dependencies.

**Spec:** `docs/superpowers/specs/2026-10-20-dotnet-taint-and-evaluation.md`

## Global Constraints

- Summary schema is version 1 and records parameter/return, sink, field-write, source/return, source/field, and sanitizer-category flows.
- High confidence requires a visible caller propagating known taint; public methods with no visible caller remain low confidence.
- Constant-only suppression applies only to private methods and internal methods without `InternalsVisibleTo`; never suppress a method with any unresolved call site.
- Unresolved calls cannot establish high-confidence taint.
- Juliet cross-file recall target is at least 60%, with no false-positive increase on identical adjudicated units.
- Controller → service → repository regression case is required; Phase 2 timing budget is measured separately from Phase 1.

## Review Focus

- Partial classes and namespaces must merge without losing or duplicating method identities.
- Equal-arity overloads and unsupported call forms must remain unresolved rather than picking an arbitrary target.
- Sanitizers must be category-specific; HTML encoding cannot clear SQL taint.
- Cycles and recursion must terminate at the documented bounds and disclose truncation.
- Constant suppression must not hide external callers of public/protected methods or methods with unresolved sites.

---

### Task 1: Define stable project and summary data contracts

**Files:**
- Create: `src/dotnet/project-index.js`
- Create: `src/dotnet/summary-schema.js`
- Create: `test/dotnet-summary-schema.test.js`

**Interfaces:**
- Produces: `SUMMARY_SCHEMA_VERSION = 1`; method summary fields are `methodId`, `parameters`, `parameterToReturn`, `parameterToSinks`, `parameterToFields`, `sourcesToReturn`, `sourcesToFields`, `sanitizersBySink`, and `unresolvedCallSites`.
- Project index records namespaces, partial type declarations, fields, methods, visibility, parameter names/types, and source spans.

- [ ] **Step 1: Add failing schema tests** for serialization/version rejection, stable method IDs across partial declarations, and namespaced type identity.
- [ ] **Step 2: Run** `node --test test/dotnet-summary-schema.test.js`; confirm missing exports/contracts.
- [ ] **Step 3: Implement** index and versioned summary constructors using AST nodes from `parseCSharp`.
- [ ] **Step 4: Verify** duplicate declarations merge only when namespace/type identity matches and distinct overloads remain distinct.
- [ ] **Step 5: Commit** schema, index, and tests.

### Task 2: Build bounded call resolution and DI mapping

**Files:**
- Create: `src/dotnet/call-resolution.js`
- Create: `test/dotnet-call-resolution.test.js`

**Interfaces:**
- Consumes: project index and AST call nodes.
- Produces: `resolveCall(call, context, index) -> { targets, status, reason }`; statuses `resolved`, `ambiguous`, or `unresolved`.

- [ ] **Step 1: Add tests** for exact name/arity, receiver type, injected field type → constructor parameter → interface, `AddScoped<I,T>`, unique implementer fallback, and ambiguous implementations.
- [ ] **Step 2: Add unresolved tests** for extension methods, equal-arity overloads, optional/named arguments, `params`, multi-target virtual/interface dispatch, delegates, and lambdas passed to higher-order APIs.
- [ ] **Step 3: Run** `node --test test/dotnet-call-resolution.test.js`; verify ambiguous/unlisted forms are unresolved.
- [ ] **Step 4: Implement** conservative resolver and increment explicit unresolved counts for every unsupported form.
- [ ] **Step 5: Verify** no unsupported call form is assigned an arbitrary target.
- [ ] **Step 6: Commit** resolver and tests.

### Task 3: Compute intra-method and inter-method flow summaries

**Files:**
- Create: `src/dotnet/method-summaries.js`
- Create: `src/dotnet/summary-fixpoint.js`
- Create: `test/dotnet-method-summaries.test.js`
- Create: `test/dotnet-summary-fixpoint.test.js`

**Interfaces:**
- Produces: `summarizeMethod(method, projectIndex, callResolver) -> MethodSummaryV1` and `propagateSummaries(index, options) -> { summaries, iterations, truncated, unresolvedCalls }`.

- [ ] **Step 1: Add summary tests** for parameter-to-return, parameter-to-sink, parameter-to-field, source-to-return/field, and source/sink category sanitizer behavior.
- [ ] **Step 2: Add fixpoint tests** for chains, cycles, depth limit, iteration limit, and deterministic output.
- [ ] **Step 3: Run** targeted tests and confirm failures before implementation.
- [ ] **Step 4: Implement** transfer summaries over AST statements and propagate with explicit configurable depth/iteration limits and cycle detection.
- [ ] **Step 5: Verify** sanitizer categories only clear covered sinks and all truncations appear in diagnostics.
- [ ] **Step 6: Commit** summary and fixpoint modules with tests.

### Task 4: Apply confidence and constant-only suppression rules

**Files:**
- Modify: `src/dotnet/summary-fixpoint.js`
- Create: `test/dotnet-constant-call-suppression.test.js`

**Interfaces:**
- Consumes: call-site constants and visibility/assembly metadata.
- Produces: findings annotated with `confidence`, `callPath`, and suppression reason where applicable.

- [ ] **Step 1: Add tests**: visible tainted path is high; public method without visible caller is low; private or internal-without-InternalsVisibleTo called only with constants is suppressed.
- [ ] **Step 2: Add tests**: public/protected methods are not constants-suppressed; any unresolved call site prevents suppression.
- [ ] **Step 3: Run** `node --test test/dotnet-constant-call-suppression.test.js`; confirm policy failures.
- [ ] **Step 4: Implement** exact visibility rules and retain unresolved call-site evidence on summaries.
- [ ] **Step 5: Verify** confidence and suppression tests pass.
- [ ] **Step 6: Commit** policy and tests.

### Task 5: Integrate findings and report call paths

**Files:**
- Modify: `src/engine.js`
- Modify: `src/rules/project.js`
- Modify: `src/report/sarif.js`
- Modify: `src/triage.js`
- Create: `test/dotnet-project-taint.test.js`

**Interfaces:**
- Consumes: complete parsed C# files and version 1 summaries.
- Produces: project findings containing `callPath`, `confidence`, `summaryVersion`, and resolver diagnostics; fallback files produce no summary and count as unresolved.

- [ ] **Step 1: Add vulnerable/safe regression pair** for controller → service → repository, including same sink called with tainted and constant-only values.
- [ ] **Step 2: Run** the focused test to confirm current project engine misses the tainted cross-file flow.
- [ ] **Step 3: Integrate** project summary analysis for complete C# files and leave unsupported/fallback file analysis intact.
- [ ] **Step 4: Add output tests** asserting full resolved path and summary version are included in JSON/SARIF/triage where supported.
- [ ] **Step 5: Verify** existing self-tests and all supplied .NET apps show no new false positives.
- [ ] **Step 6: Commit** integration and regression cases.

### Task 6: Score and gate Phase 2

**Files:**
- Modify: `scripts/compare-dotnet.js`
- Create: `docs/benchmarks/dotnet-project-taint-phase-report.json`
- Modify: `docs/DOTNET-COVERAGE.md`

- [ ] **Step 1: Run** frozen Juliet cross-file unit scorer and all tiered labeled .NET sets at CLI default confidence; report medium+ separately.
- [ ] **Step 2: Compare** false positives on identical units, per CWE/confidence; record Phase 2 scan time separately from parser Phase 1.
- [ ] **Step 3: Confirm** >=60% cross-file recall and no FP increase; if missed, keep changes opt-in or do not ship by default.
- [ ] **Step 4: Record** engine SHA, dataset manifests, unresolved/truncation counts, paths, timings, and adjudication limits.
- [ ] **Step 5: Commit** immutable report and coverage update.

