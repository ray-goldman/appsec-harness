# MVC Constant SQL Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans. Implement natively and use two fresh reviewers before the PR.

**Goal:** Remove the remaining modeled MVC constant SQL false positive while preserving dynamic and ambiguous SQL warnings.

**Architecture:** Keep the existing source-constant proof. Add a small framework-owner predicate backed by a pinned .NET 10 inherited-name profile; use it as an alternative to the current source-interface-only base guard. Every later source/constant check remains required.

**Tech Stack:** Node.js >=20, built-ins and existing C# token infrastructure. No installed runtime dependencies.

**Spec:** `docs/superpowers/specs/2026-10-23-mvc-constant-sql.md`.

## Global constraints

- Frozen target/key/evaluator bytes unchanged; no target execution, builds or dependency installs.
- Standalone supported SDK/default-compile project, complete bounded inputs and literal const strings only.
- Unknown framework/build/binding forms retain warnings; profile assumptions and provenance must be explicit.
- No TP losses or new FPs in seven suites and earlier frozen replays. No recall claim from the safe-only set.
- Both fresh reviews before PR; no merge or release in this task.

## Review focus

- Framework namespace/type look-alikes must not select an external inherited surface.
- Current-owner and inherited value names must beat imported const types in expression lookup.
- Inheritance combinations, records/interfaces and unknown build overrides must decline.
- Qualified names, contextual tokens and source-interface decoys must retain earlier defenses.
- Corpus and benchmark evidence must keep exact source identities, keys, denominators and exposure tiers.

## Task 1: Bounded MVC binding and evidence

**Files:** add `src/csharp-mvc-binding.js`, `src/frameworks/aspnetcore-controllerbase-net10.json`, `test/csharp-mvc-const.test.js`, paired corpus and evidence docs; modify only the base-owner guard in `src/csharp-const-members.js` and npm test list.

- [x] Reproduce baseline, inspect the remaining SQL path and retain official immutable API source data.
- [x] Add failing direct/qualified MVC positive regressions and passing inherited-value/custom-base near neighbors.
- [x] Implement the pinned profile and narrow owner predicate; retain all current proof guards.
- [x] Run focused/full tests and the regression corpus; add every review repro as a regression.
- [x] Complete fresh review pass 1 and fix important findings.
- [x] Freeze code and rerun all seven suites, new safe set and earlier frozen/FinSuite replays; compare every unit under unchanged policies.
- [x] Complete fresh review pass 2, fix findings and rerun affected gates on a new immutable phase if code changes.
- [ ] Publish sanitized aggregates, commit, push/open/attach the PR after final verification.
