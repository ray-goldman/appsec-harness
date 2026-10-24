# Rust coverage and Cargo inventory implementation plan

> **For agentic workers:** Use superpowers:executing-plans. The implementer works locally; two fresh reviewers inspect the result before a PR.

**Goal:** Make unsupported source analysis visible and inventory Cargo resolutions without executing Cargo or changing established source detections.

**Architecture:** Add additive `coverage` and `dependencyInventory` fields to findings@1. A bounded TOML reader feeds Cargo inventory; lockfiles are authoritative. Keep the severity gate intact and expose a separate opt-in coverage gate across CLI, MCP and report formats.

**Tech stack:** Node.js >=20, built-ins only, Windows and Linux.

**Spec:** The user-approved Hermes assessment (local evidence, SHA-256 `7fc26cf18d10eaac432dc7b1028b1d176570b23b7a8d9288972e3e886a8fea26`). Its first two phases are implemented here. Rust source rules require a later syntax/evidence design.

## Global constraints

- Static reads only; never execute target apps, Cargo, builds or package scripts.
- No installed runtime dependencies. Preserve source findings and frozen evaluation policy/keys.
- Separate source, inventory and advisory coverage; general text checks are not Rust SAST.
- Query only exact canonical crates.io resolutions with opt-in OSV. Never query Git, local or private registry identities.
- Ship only verified, pinned advisory data; show its date and limited scope. No dependency reachability claims.
- Publish scanner-owned tests and sanitized aggregate results only.

## Coverage contract

`coverage` has schema `kayfabe/coverage@1`, source, inventory, advisories and scope sections. Source counts known source languages selected by the walker, distinguishing supported checks from unsupported languages. Unsupported Rust/C/C++/Swift/Dart files and unintended read/size/depth/count limits make source coverage incomplete. Supported means some source rules ran, not exhaustive detection or parsing. C# parser fallback remains separately reported.

Default exclusions (tests, vendored/build directories and explicit exclusions) are disclosed as scan scope, not claimed analyzed. `--require-coverage` requires supported source checks for selected known source files, no unintended traversal/read limits, and no incomplete Cargo inventory. Empty/old reports cannot satisfy it. It does not require an exhaustive advisory database; advisory breadth is always limited and shown separately. `--no-gate` overrides exit enforcement only. Severity and coverage results remain separate in JSON; JUnit has a separate coverage case, SARIF properties/notifications carry coverage, and human reports display it beside the severity gate. Legacy reports have unknown coverage, never inferred complete.

Cargo supports lock formats 2–4; basic/literal strings, scalar values, arrays, inline/dotted dependency tables, target sections and workspace inheritance. Unsupported syntax, duplicate keys, invalid identities, missing workspace inputs and ambiguous source identities produce explicit diagnostics rather than fabricated versions. Registry source and checksum are retained after credential redaction. Sourceless lock entries are classified as root/workspace only with visible matching manifests, otherwise local/unknown. Manifest requirements are not resolved versions. Workspace lock ownership uses visible workspace membership; no filesystem escape or recursive reads.

## Review focus

1. A green severity gate with unsupported/omitted source must visibly remain incomplete.
2. Nested workspaces, renames, overrides and same-name private crates must not invent public identities.
3. Hostile TOML, excessive nesting, duplicates and prototype keys must fail boundedly without guessed dependencies.
4. Online failure/pagination/detail limits and a tiny offline snapshot must never imply exhaustive advisory coverage.
5. Credentials in metadata and markup in diagnostics must not leak into new inventory/report output.

## Tasks

### 1. Bounded Cargo inventory

Files: `src/supply/toml.js`, `src/supply/cargo.js`, `src/supply/manifests.js`, `src/supply/index.js`, `test/cargo-inventory.test.js`.

- [ ] Write failing parser/integration tests for canonical, Git/private/local entries, manifest ranges, aliases/workspaces, duplicate/unsupported input, resource limits and redaction.
- [ ] Run targeted tests and save the failure log.
- [ ] Implement `parseCargo(rel, raw)` returning deps, hygiene, diagnostics and document metadata; `analyzeCargo(files)` returns inventory and per-input coverage. Lock resolutions supersede manifest declarations; retain unresolved declarations explicitly.
- [ ] Add public crates.io OSV eligibility and verified offline advisory subset with pinned provenance/date; test vulnerable/fixed versions and private-source controls.
- [ ] Run targeted tests and commit the tested implementation.

### 2. Coverage and report policy

Files: `src/coverage.js`, `src/engine.js`, `src/walker.js`, `src/cli.js`, `src/mcp/server.js`, `src/report/*.js`, `test/coverage-reporting.test.js`, `package.json`.

- [ ] Write failing scan/report/CLI/MCP tests for unsupported/large/unreadable Rust, supported sources, no source, Cargo partial results, old reports and independent gates.
- [ ] Implement `buildCoverage(...)`, `coverageGate(result, required)` and stable summary text. Keep existing `gate()` semantics.
- [ ] Wire inventory/coverage through scan, JSON, Markdown, HTML, SARIF, JUnit and MCP; escape untrusted metadata. Add CLI `--require-coverage` to scan/audit/report/gate.
- [ ] Run targeted tests, full tests and selftest; commit.

### 3. Evidence, reviews and PR

- [ ] Run all seven unchanged benchmark suites against frozen main and candidate archives; compare every decision and pinned scoring/input identity.
- [ ] Replay all frozen C#/C/FinSuite apps, nine app sets, adversarial fixtures and both Hermes variants. Preserve true positives and no new adjudicated false positives.
- [ ] Fresh review pass one: code, parser/source privacy and fail-closed boundaries. Fix issues and repeat affected verification.
- [ ] Fresh review pass two: code plus measured evidence, unchanged keys/scorers, report consistency and documentation claims. If code changes after measurement, freeze a new candidate and repeat the suite.
- [ ] Publish sanitized result/limits documentation, push the branch and open/attach a PR after both passes. No merge or release in this task.
