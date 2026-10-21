# .NET Framework and Authorization Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Model ASP.NET routes and effective authorization conservatively, then add focused middleware, request-protection, data-layer, and deserialization checks.

**Architecture:** Reuse the project index and version 1 method summaries. Build route and authorization policy facts in a dedicated module, keep route-level authorization distinct from object-level checks, and put focused checks behind paired safe/vulnerable tests. Each new check is adjudicated on the frozen real-repository sample before default enablement.

**Tech Stack:** Node.js plain JavaScript, current C# AST/project analysis, existing rule and report infrastructure; no new dependencies.

**Spec:** `docs/superpowers/specs/2026-10-20-dotnet-taint-and-evaluation.md`

## Global Constraints

- Support MVC controllers/actions, Razor Pages, minimal API routes/groups, and hubs only where statically visible.
- Effective authorization includes attribute inheritance, `[AllowAnonymous]`, endpoint/group conventions, MVC `AuthorizeFilter`, and visible fallback policy.
- Flag unsafe-verb and admin-like endpoints only when no effective policy is established; report heuristic administrative findings separately.
- Route authorization and object-level authorization are distinct facts for IDOR analysis.
- Every new check ships with a vulnerable/safe corpus pair and is evaluated on adjudicated real-repository data before default enablement.
- Authorization labels require >=70% recall and no regression on previously measured tiers; a spent holdout cannot be retuned against.

## Review Focus

- `[AllowAnonymous]` must override inherited or group authorization only at its applicable endpoint scope.
- `RequireAuthorization` on a route group or `MapControllers()` must propagate to mapped endpoints.
- Global MVC filters and fallback policy must prevent missing-auth findings when statically established.
- Admin-like route/name heuristics must not be conflated with unsafe HTTP verbs or reported as equivalent evidence.
- Middleware order must be interpreted across both minimal hosting and `Startup.Configure` without guessing across conditional branches.

---

### Task 1: Build route and effective-policy model

**Files:**
- Create: `src/dotnet/routes.js`
- Create: `src/dotnet/authorization.js`
- Create: `test/dotnet-authorization.test.js`

**Interfaces:**
- Consumes: parsed project AST, project index, summary schema v1.
- Produces: route records with `routeId`, `framework`, `verb`, `sourceSpan`, `authEvidence`, `effectivePolicy`, `objectLevelChecks`, and `unresolvedPolicyReasons`.

- [ ] **Step 1: Add failing tests** for MVC controller/action attributes and inheritance, Razor Pages conventions, minimal API route methods, route groups, and hubs.
- [ ] **Step 2: Add policy tests** for `[AllowAnonymous]`, `[Authorize]`, `MapControllers().RequireAuthorization()`, group `RequireAuthorization`, `AuthorizeFilter`, and visible fallback policy.
- [ ] **Step 3: Run** `node --test test/dotnet-authorization.test.js`; confirm route/policy extraction failures.
- [ ] **Step 4: Implement** route collection and scope-aware policy composition; unresolved dynamic registration is represented explicitly.
- [ ] **Step 5: Verify** inherited, anonymous, group, global-filter, and fallback cases resolve as expected.
- [ ] **Step 6: Commit** route model and tests.

### Task 2: Add missing authorization and IDOR checks

**Files:**
- Modify: `src/rules/csharp.js`
- Modify: `src/rules/project.js`
- Create: `test/dotnet-route-auth.test.js`

**Interfaces:**
- Consumes: route records and method summaries.
- Produces: separate findings for unsafe-verb missing policy, administrative heuristic missing policy, and object-level authorization gaps.

- [ ] **Step 1: Add paired safe/vulnerable tests** for unauthenticated state-changing endpoint, admin-like route, inherited policy, and object ID access guarded by ownership check.
- [ ] **Step 2: Run** focused tests and confirm current behavior.
- [ ] **Step 3: Implement** checks that require absent effective policy; emit separate rule IDs and evidence for admin-like heuristics.
- [ ] **Step 4: Verify** safe pairs remain quiet and route-level auth does not imply object-level authorization.
- [ ] **Step 5: Commit** rules and tests.

### Task 3: Add bounded middleware and request-protection checks

**Files:**
- Create: `src/dotnet/middleware.js`
- Modify: `src/rules/csharp.js`
- Create: `test/dotnet-middleware.test.js`

**Interfaces:**
- Produces: findings for authentication/authorization order, CORS placement, HTTPS/HSTS, login rate limiting, CSP/security headers, and anti-forgery on cookie-authenticated unsafe verbs.

- [ ] **Step 1: Add paired tests** for minimal hosting and `Startup.Configure` order, CORS placement, and HTTPS/HSTS configuration.
- [ ] **Step 2: Add paired tests** for login rate limit, CSP/security headers, and unsafe cookie-authenticated forms with and without anti-forgery validation.
- [ ] **Step 3: Run** targeted tests to establish current gaps.
- [ ] **Step 4: Implement** bounded sequence and route/config checks over supported syntax; report unresolved conditional ordering rather than guessing.
- [ ] **Step 5: Verify** all pairs and confirm uncertain configurations produce no high-confidence finding.
- [ ] **Step 6: Commit** checks and tests.

### Task 4: Add data-layer and deserialization summaries

**Files:**
- Modify: `src/dotnet/method-summaries.js`
- Create: `src/dotnet/framework-sinks.js`
- Modify: `src/rules/csharp.js`
- Create: `test/dotnet-framework-sinks.test.js`

**Interfaces:**
- Produces: sink/source categories for EF Core raw SQL wrappers, `string.Format` SQL, Dynamic LINQ, System.Text.Json polymorphism/settings, MessagePack typeless, and YamlDotNet.

- [ ] **Step 1: Add safe/vulnerable flow tests** for each supported database wrapper and sanitizer category.
- [ ] **Step 2: Add safe/vulnerable deserialization configuration tests** including settings passed through variables.
- [ ] **Step 3: Run** focused tests and confirm unsupported configurations remain unresolved.
- [ ] **Step 4: Implement** framework models using summary schema v1; avoid rule-specific one-off call patterns.
- [ ] **Step 5: Verify** no cross-category sanitizer clears unrelated taint and paired safe cases remain quiet.
- [ ] **Step 6: Commit** models and tests.

### Task 5: Score and gate Phase 3

**Files:**
- Modify: `scripts/compare-dotnet.js`
- Create: `docs/benchmarks/dotnet-framework-phase-report.json`
- Modify: `docs/DOTNET-COVERAGE.md`

- [ ] **Step 1: Run** every new check on its frozen vulnerable/safe corpus pairs and the adjudicated real-repository sample.
- [ ] **Step 2: Record** per-rule findings, adjudicated FP counts, unresolved framework constructs, per-tier regression results, and authorization recall.
- [ ] **Step 3: Confirm** >=70% recall on independent authorization labels with no regression; keep any missed-gate checks opt-in or omit them from default behavior.
- [ ] **Step 4: Record** manifests, scorer/engine versions, confidence threshold, and whether the independent holdout is spent.
- [ ] **Step 5: Commit** immutable report and coverage update.

