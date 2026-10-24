# Constant Member SQL Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans. Implement natively; use fresh agents for the two requested review passes.

**Goal:** Reduce the verified SQL false positives wherever source binding can be proved, retaining unresolved or mutable SQL inputs.

**Architecture:** Add a bounded source/project constant-member proof and apply it only to remaining `CS-SQLI-001` CommandText candidates. Keep existing constant and taint paths unchanged.

**Tech Stack:** Node.js 20+, built-ins, existing C# lexer/parser; no installed dependencies.

**Spec:** `docs/superpowers/specs/2026-10-23-const-member-sql.md`.

## Global constraints

- Preserve supplied archives, exact app/key bytes and original baseline; label the set development and safe-only.
- Unsupported C cases cannot earn true negatives. Do not report recall from this set.
- One supported standalone SDK/default-compile project, complete bounded inputs, literal const strings only; unsupported forms retain findings.
- No app builds/tests/dependency installs. Scanner-owned fixtures/tests and static evaluation only.
- All seven benchmarks keep their keys and policies; reject TP losses/new FPs. Two fresh reviews before a separate PR.

## Task 1: Evidence, proof and verification

**Files:** add `src/csharp-const-members.js`, `test/csharp-const-members.test.js` and paired corpus case; modify the final SQL candidate filter in `src/engine.js`, npm test list and evidence docs. Local evaluator scripts/reports remain outside the repository; publish sanitized aggregates only.

- [x] Freeze inputs/provenance/policy, validate labels, measure baseline and adjudicate unmatched SQL warning.
- [x] Add failing public scanner regressions for ordinary/raw cross-file constant interpolation.
- [x] Implement the narrow proof and guards. Add mutable fields/properties, shadowing, extra tainted holes, suffixes, aliases, ambiguity, conditional/unknown project input and bounds tests.
- [x] Run focused/full tests and paired corpus; fix failures at their cause.
- [x] Complete fresh review pass 1, fix important findings and repeat verification.
- [x] Freeze implementation and rerun the new set and all seven existing suites; compare exact inputs/policies and per-unit transitions.
- [x] Complete fresh review pass 2, verify evidence and documented limits, fix findings and repeat affected gates.
- [ ] Push/open/attach a separate PR after verification; do not merge without a later request.
