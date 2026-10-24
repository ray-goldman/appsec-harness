# Confined File Reads Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans. The user selected native implementation and requires two review passes before the PR.

**Goal:** Close the demonstrated MCP junction escape and the equivalent triage evidence/context paths.

**Architecture:** Add one bounded, descriptor-based source reader. MCP and triage consume it; neither retains a pathname-only source read after validation.

**Tech Stack:** Node.js 20+, built-in filesystem/path APIs, node:test; no installed dependencies.

**Spec:** `docs/superpowers/specs/2026-10-23-confined-file-reads.md`.

## Global constraints

- Base `8d3ffb9bf98d50ee28a1667a33f680594001f072`; preserve unrelated files and the old self-audit evidence.
- Reject descendant links, unsupported path forms and nonregular files; preserve ordinary relative files and selected root aliases.
- Read at most 1 MiB through a verified descriptor, with cleanup and mutation checks.
- Do not execute target apps or real updater installations; controlled dummy filesystem probes and scanner tests are authorized.
- State portable race/hard-link limits; do not claim a fully atomic sandbox.

## Review focus

- Windows junctions, case/separator/drive/stream forms and prefix siblings must not cross the selected root.
- Every evidence channel and the MCP findings/search/context paths must share the guard.
- Root/component/file replacement between checks, opening and reading must not silently expose outside bytes.
- Nonregular/oversized/changing files must not block indefinitely or allocate unbounded buffers; descriptors close on failure.
- Normal source reads, root aliases, redacted triage context and existing report behavior must remain usable.

### Task 1: Implement and verify the shared read boundary

**Files:** create `src/confined-read.js` and `test/file-confinement.test.js`; modify `src/mcp/server.js`, `src/triage.js`, `package.json`; add security/result documentation.

**Interface:** `readConfinedText(root, relativeFile)` returns UTF-8 source text or throws on unsupported/unsafe/unreadable input. Callers decide whether failure is an MCP error, invalid evidence or unavailable context.

- [x] Add public-API regressions for the original escape and ordinary reads, all evidence channels, context/search behavior, leaf and ancestor links, prefix/absolute inputs and root aliases. Observe failures before implementation.
- [x] Implement canonical/component checks and descriptor reads with bounded bytes, identity/mutation checks and cleanup; integrate all four consumers.
- [x] Add deterministic swap, oversized-file and descriptor-cleanup regressions; run focused tests, full tests and selftest.
- [x] Complete fresh review pass 1, fix important findings with red/green evidence, and repeat verification.
- [x] Freeze the implementation; rerun production and full-default self-audits plus the original controlled boundary probe, retaining all old artifacts.
- [x] Complete fresh review pass 2, verify claims and remaining limitations, fix findings and repeat affected checks.
- [ ] Commit evidence/documentation, push the branch, open and attach the PR, and confirm CI. Do not merge without a later request.
