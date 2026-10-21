# .NET Stored Data, NuGet, and Triage Evaluation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add opt-in stored-data flows, verify and snapshot NuGet advisories, improve dependency reachability reporting, and measure triage-agent accuracy without leaking labels.

**Architecture:** Keep stored-data findings under a separate CLI option and distinct rules. Quarantine unverified advisories from authoritative runtime data, generate a pinned offline snapshot as a maintainer operation, and extend triage evidence with project context while keeping evaluation labels outside model input.

**Tech Stack:** Node.js plain JavaScript, existing supply-chain and triage modules, Node crypto and test runner; network access only for an explicitly run snapshot-generation step.

**Spec:** `docs/superpowers/specs/2026-10-20-dotnet-taint-and-evaluation.md`

## Global Constraints

- Stored-data analysis is opt-in, uses separate stored XSS and second-order SQL rule IDs, and has low default confidence.
- Evaluate incremental precision/recall on the adjudicated real-repository sample before changing defaults.
- Every authoritative advisory has verified identifier, affected range, source, date, and provenance; unverified advisories are quarantined or omitted.
- Offline scans read only a pinned snapshot and show its snapshot date.
- Read supported lock files and `project.assets.json`; reachability-lite requires conservative vulnerable API references.
- Scanner and triage-agent accuracy remain separate; each triage item is run at least three times with model, prompt, and sampling settings pinned.
- Keep labels, adjudication notes, and scorer output out of the triage agent's context.

## Review Focus

- Stored data must not silently enter default taint flows or change default findings.
- Advisory ranges must use the correct NuGet package identity and inclusive/exclusive version boundaries.
- Transitive dependencies must not be confused with direct dependencies or duplicated across manifests.
- Snapshot-generation network access must not be required during an ordinary scan.
- Triage evaluation must not expose truth labels, adjudication notes, or scorer feedback to the model being measured.

---

### Task 1: Add explicit stored-data mode

**Files:**
- Modify: `src/cli.js`
- Modify: `src/dotnet/method-summaries.js`
- Modify: `src/rules/csharp.js`
- Create: `test/dotnet-stored-data.test.js`

**Interfaces:**
- Produces: `--stored-data` option; separate rules `DOTNET-STORED-XSS` and `DOTNET-SECOND-ORDER-SQL`; disabled unless explicitly requested.

- [ ] **Step 1: Add tests** proving database/file-read sources do not affect default results and do affect opt-in flows.
- [ ] **Step 2: Add paired safe/vulnerable tests** for stored XSS and second-order SQL injection; assert low confidence and distinct rule IDs.
- [ ] **Step 3: Run** `node --test test/dotnet-stored-data.test.js`; confirm option/rules are absent.
- [ ] **Step 4: Implement** option-gated summaries and report metadata identifying stored-data mode.
- [ ] **Step 5: Verify** default scan output is unchanged and opt-in output reports mode explicitly.
- [ ] **Step 6: Commit** CLI, summaries, rules, and tests.

### Task 2: Document deliberate Juliet non-detections

**Files:**
- Modify: `docs/DOTNET-COVERAGE.md`
- Modify: `docs/DETECTION-GAPS.md`
- Test: `test/dotnet-coverage.test.js`

- [ ] **Step 1: Add documentation assertions** for four zero-coverage categories and disposition of CWE-209 responses, `new Random()`, plain-HTTP URLs/CWE-319, and CWE-506.
- [ ] **Step 2: Run** `node --test test/dotnet-coverage.test.js` and identify missing rationale.
- [ ] **Step 3: Document** what is deliberately detected, deferred, or not security-relevant and why.
- [ ] **Step 4: Verify** all four zero-coverage categories have a recorded disposition and no score is represented as accuracy evidence.
- [ ] **Step 5: Commit** coverage/gap documentation and tests.

### Task 3: Verify current NuGet advisories

**Files:**
- Modify: `src/supply/advisories.js`
- Create: `docs/benchmarks/nuget-advisory-provenance.json`
- Create: `test/nuget-advisory-provenance.test.js`

**Interfaces:**
- Produces: advisory records with `package`, `advisoryId`, `sourceUrl`, `affectedRange`, `verifiedAt`, `provenance`, and `verified` state.

- [ ] **Step 1: Add tests** requiring every active authoritative advisory to have source, identifier, affected range, date, and provenance; reject unverified records from authoritative matching.
- [ ] **Step 2: Run** `node --test test/nuget-advisory-provenance.test.js`; confirm currently unverified entries fail.
- [ ] **Step 3: Verify** each curated advisory against authoritative GHSA/NVD/OSV records and record exact range semantics; quarantine entries that cannot be verified.
- [ ] **Step 4: Implement** validation that prevents quarantined entries from matching as authoritative findings.
- [ ] **Step 5: Verify** active records all meet provenance requirements and quarantined records never emit authoritative results.
- [ ] **Step 6: Commit** advisory updates, provenance, and tests.

### Task 4: Generate and consume pinned offline advisory snapshot

**Files:**
- Create: `scripts/update-osv-nuget-snapshot.js`
- Create: `data/advisories/nuget-osv-snapshot.json`
- Modify: `src/supply/advisories.js`
- Modify: `src/report/markdown.js`
- Test: `test/nuget-offline-snapshot.test.js`

**Interfaces:**
- Produces: maintainer command `npm run update:nuget-snapshot`; ordinary scans load local snapshot and report date/provenance without network access.

- [ ] **Step 1: Add tests** for snapshot schema, provenance pinning, offline lookup, and visible snapshot date.
- [ ] **Step 2: Run** `node --test test/nuget-offline-snapshot.test.js`; verify the offline reader and metadata requirements fail.
- [ ] **Step 3: Implement** snapshot generation as a separate network-using maintainer operation; pin source records and hashes.
- [ ] **Step 4: Implement** read-only snapshot consumption in scans; ensure it makes no network request.
- [ ] **Step 5: Verify** a scan succeeds with network disabled and reports snapshot date and source.
- [ ] **Step 6: Commit** generator, snapshot, consumer, and tests.

### Task 5: Read transitive assets and add conservative reachability-lite

**Files:**
- Modify: `src/supply/manifests.js`
- Modify: `src/supply/index.js`
- Create: `src/supply/nuget-assets.js`
- Create: `test/nuget-assets.test.js`

**Interfaces:**
- Produces: dependency records containing package ID, resolved version, direct/transitive origin, manifest source, and optional `reachableApi` evidence.

- [ ] **Step 1: Add fixtures/tests** for supported lock files and `project.assets.json`, direct/transitive duplicates, version conflicts, and malformed manifests.
- [ ] **Step 2: Add reachability tests** where a vulnerable API reference is present, absent, or ambiguous.
- [ ] **Step 3: Run** `node --test test/nuget-assets.test.js`; confirm parsing and conservative reachability fail.
- [ ] **Step 4: Implement** asset ingestion and deduplication; only mark reachable when a vulnerable API reference is directly established.
- [ ] **Step 5: Verify** malformed/ambiguous assets do not create high-confidence reachability claims.
- [ ] **Step 6: Commit** asset support and tests.

### Task 6: Add project/auth context to triage requests

**Files:**
- Modify: `src/triage.js`
- Modify: `src/engine.js`
- Create: `test/dotnet-triage-context.test.js`

**Interfaces:**
- Produces: triage item fields `callPath`, `routeAuthContext`, `effectivePolicy`, and `summaryVersion`, omitted when unknown.

- [ ] **Step 1: Add tests** for present/absent project path and route-policy context; assert labels and adjudication metadata are never serialized into agent input.
- [ ] **Step 2: Run** `node --test test/dotnet-triage-context.test.js`; confirm missing fields and leakage guards.
- [ ] **Step 3: Implement** context propagation using project findings, omitting unknown values rather than guessing.
- [ ] **Step 4: Verify** existing triage request shape remains compatible and the leakage guard passes.
- [ ] **Step 5: Commit** context enrichment and tests.

### Task 7: Evaluate triage accuracy and Phase 4/5 gates

**Files:**
- Create: `scripts/evaluate-triage.js`
- Create: `docs/benchmarks/dotnet-triage-evaluation-policy.md`
- Create: `docs/benchmarks/dotnet-stored-data-nuget-phase-report.json`
- Modify: `docs/DOTNET-COVERAGE.md`

- [ ] **Step 1: Define** label-isolated evaluation input/output boundaries and immutable per-run metadata: model ID, prompt version, sampling settings, and repeat index.
- [ ] **Step 2: Add tests** for three-run minimum, variance calculation, real-finding dismissal rate, safe-code confirmation rate, and no labels/notes/scorer output in model context.
- [ ] **Step 3: Implement** evaluator with at least three independent runs per item; store predictions separately from labels until scoring.
- [ ] **Step 4: Run** opt-in stored-data checks against the adjudicated repo sample and report incremental precision/recall; leave default disabled unless evidence supports a change.
- [ ] **Step 5: Record** advisory verification/snapshot provenance, asset coverage, reachability limits, triage metrics, and dataset tiers.
- [ ] **Step 6: Verify** all reports include engine/scorer versions, manifests, measured/not-measured gates, and never combine scanner accuracy with triage accuracy.
- [ ] **Step 7: Commit** evaluation policy, scripts, reports, and docs.

