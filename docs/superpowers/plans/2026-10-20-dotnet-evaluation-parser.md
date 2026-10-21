# .NET Evaluation Protocol and Parser Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Freeze a tiered, auditable .NET evaluation protocol and add a bounded C# parser with visible coverage and safe regex fallback.

**Architecture:** Keep scoring policy and dataset provenance in dedicated benchmark modules. Add a lexer/parser under `src/parsers/csharp/`, expose parse results and coverage to the project engine, and preserve existing checks as fallback whenever a file is unsupported or malformed. Phase 0 protocol work and Phase 1 parser work may proceed in parallel, but the Juliet cross-file baseline must use the frozen unit policy before Phase 2 begins.

**Tech Stack:** Node.js plain JavaScript, existing `node:test` suite, SHA-256 via Node built-ins; no new dependencies.

**Spec:** `docs/superpowers/specs/2026-10-20-dotnet-taint-and-evaluation.md`

## Global Constraints

- Dataset tiers are self-authored regression, independently authored, and third-party real code; never aggregate their scores.
- Independent authors must never have seen Kayfabe rules, labeled corpus, benchmark apps, or scorer; an LLM author must also have a pre-publication training cutoff.
- Publish SHA-256 manifest, scorer version, engine commit, scoring policy, tier, and phase before each scheduled score.
- A holdout is scored once per phase and is retired to development after results inform a rule or analysis change.
- Juliet cross-file units are frozen before Phase 2; CLI default confidence `low` decides gates.
- Parse at least 95% of methods in the frozen coverage fixtures; report file and method coverage and fallback use.
- Parser scan time is at most 1.5× the current scanner on the same fixed inputs; Phase 2 has a separate time budget.
- No dependencies beyond Node built-ins; `.cshtml` and `.razor` remain on regex analysis.

## Review Focus

- Unterminated strings/comments or malformed syntax must select regex fallback and count as unparsed.
- Nested interpolation braces, raw strings, and format specifiers must not corrupt token boundaries.
- Preprocessor branches must all be parsed while preserving `OMITBAD`/`OMITGOOD` regions.
- Early exits, switch sections, and try/catch/finally edges must not imply assignments dominate paths where they do not.
- Files that fall back must still receive the existing regex checks and must not be counted as parser coverage.

---

### Task 1: Freeze dataset policy and current provenance

**Files:**
- Create: `docs/benchmarks/dotnet-evaluation-policy.md`
- Create: `docs/benchmarks/dotnet-datasets.json`
- Create: `docs/benchmarks/dotnet-independent-author-brief.md`
- Modify: `docs/DOTNET-COVERAGE.md`
- Test: `test/dotnet-evaluation-policy.test.js`

**Interfaces:**
- Produces: dataset records with `id`, `tier`, `status`, `source`, `revision`, `seenChanges`, `manifestPath`, and `labelPolicy`.

- [ ] **Step 1: Add policy tests** asserting own apps are tier 1; Juliet is tier 3/seen with held half retired; eShop and WebGoat.NET are tier 3/seen and excluded from public-repo sampling; existing held-out labels are not called blind.
- [ ] **Step 2: Run** `node --test test/dotnet-evaluation-policy.test.js`; confirm failures identify missing policy/data.
- [ ] **Step 3: Implement** policy and dataset records; document WebGoat adjudication states, public-repository eligibility/exclusions, dual-adjudicator disagreement resolution, and “not measured” semantics.
- [ ] **Step 4: Write the independent author brief** using only application features and the precommitted CWE list; include safe twins, required label fields, isolation declaration, and model cutoff/publication-date checks. Store the brief separately from source and labels.
- [ ] **Step 5: Arrange an isolated author and custodian** who meet the spec. If no qualified author is available, explicitly mark the independent tier not measured and do not substitute self-authored apps.
- [ ] **Step 6: Verify** `node --test test/dotnet-evaluation-policy.test.js` passes and existing benchmark commands remain unchanged.
- [ ] **Step 7: Commit** policy, dataset registry, author brief, test, and coverage doc update.

### Task 2: Freeze public-repository sampling frame and adjudication workflow

**Files:**
- Create: `docs/benchmarks/dotnet-repository-sample.json`
- Create: `docs/benchmarks/dotnet-finding-adjudication.md`
- Create: `scripts/freeze-dotnet-repositories.js`
- Test: `test/dotnet-repository-sample.test.js`

**Interfaces:**
- Produces: immutable repository records with canonical URL, license, eligibility rationale, revision SHA, exclusion status, and sample stratum.

- [ ] **Step 1: Add tests** requiring 30–50 eligible application repositories, excluding eShop/WebGoat.NET and forks/templates/generated samples, with immutable revision IDs.
- [ ] **Step 2: Run** `node --test test/dotnet-repository-sample.test.js`; confirm incomplete/mutable sample records fail.
- [ ] **Step 3: Implement** sample validation/freeze tooling and the dual-adjudicator protocol, including agreement and disagreement resolution fields.
- [ ] **Step 4: Verify** the frozen sample meets declared selection criteria before any scan; capture SHA-256 manifest.
- [ ] **Step 5: Commit** sample manifest and adjudication protocol. Repository selection and adjudication are human-reviewed inputs; do not infer labels from scanner output.

### Task 3: Freeze Juliet cross-file unit scoring

**Files:**
- Modify: `src/benchmark-juliet.js`
- Create: `docs/benchmarks/dotnet-juliet-cross-file-units.json`
- Modify: `scripts/compare-dotnet.js`
- Test: `test/dotnet-juliet-units.test.js`

**Interfaces:**
- Produces: exported `scoreJulietUnits({ findings, labels, units, confidenceThreshold })` returning per-CWE `tp`, `fp`, `tn`, `fn`, `recall`, with units identified as file or multi-file testcase.

- [ ] **Step 1: Add failing tests** for file×CWE×polarity scoring and multi-file testcase scoring; include variants 22a/b, 51–54, 61, 66–68, 71–75, and 81, and assert bad/good regions and finding CWE matching.
- [ ] **Step 2: Run** `node --test test/dotnet-juliet-units.test.js`; confirm the current scorer splits units incorrectly.
- [ ] **Step 3: Implement** the frozen unit manifest and scorer; use CLI `low` as gate threshold and emit `medium+` results as secondary metrics.
- [ ] **Step 4: Verify** unit tests and regenerate a Phase 2 baseline report before any project-wide taint change; include unit list hash and engine SHA.
- [ ] **Step 5: Commit** scorer, unit manifest, report metadata, and tests.

### Task 4: Add C# lexer with source spans

**Files:**
- Create: `src/parsers/csharp/lexer.js`
- Create: `test/csharp-lexer.test.js`

**Interfaces:**
- Produces: `tokenizeCSharp(source) -> { tokens, regions, errors }`; each token has `kind`, `text`, `start`, `end`; regions include preprocessor and Juliet omission spans.

- [ ] **Step 1: Add failing tests** for comments, char literals, regular/verbatim/interpolated/raw/UTF-8 strings, nested interpolation braces, format specifiers, and `#if/#elif/#else/#endif` region spans.
- [ ] **Step 2: Run** `node --test test/csharp-lexer.test.js`; confirm missing API and boundary failures.
- [ ] **Step 3: Implement** tokenizer with explicit lexical states; nested interpolation expressions reuse tokenization while string text remains opaque.
- [ ] **Step 4: Add failing error tests** for unterminated strings/comments and unmatched directives, then implement recoverable lexer errors that mark the file incomplete.
- [ ] **Step 5: Verify** lexer tests pass and malformed source never returns a complete token stream.
- [ ] **Step 6: Commit** lexer and tests.

### Task 5: Parse supported declarations, statements, and expressions

**Files:**
- Create: `src/parsers/csharp/parser.js`
- Create: `test/csharp-parser.test.js`

**Interfaces:**
- Consumes: `tokenizeCSharp(source)`.
- Produces: `parseCSharp(source) -> { complete, declarations, methods, regions, errors, coverage }`; AST nodes carry source spans. Statements include explicit block/control-flow nodes and exit edges.

- [ ] **Step 1: Add failing tests** for namespaces/types/records/partials, fields/properties/attributes, methods/constructors/parameters, lambdas/local functions, and supported expression nodes.
- [ ] **Step 2: Add control-flow tests** for if/else, switch sections, try/catch/finally, loops, using, return/throw/break/continue and branch-local assignment spans.
- [ ] **Step 3: Run** `node --test test/csharp-parser.test.js`; confirm unsupported parse cases are reported incomplete.
- [ ] **Step 4: Implement** recursive descent over the declared subset; reject goto, unsafe code, or unhandled grammar with an incomplete result rather than inventing structure.
- [ ] **Step 5: Verify** all parser fixtures produce expected node spans and that all preprocessor branches are represented.
- [ ] **Step 6: Commit** parser and tests.

### Task 6: Integrate regex fallback and coverage reporting

**Files:**
- Create: `src/parsers/csharp/coverage.js`
- Modify: `src/engine.js`
- Modify: `src/cli.js`
- Modify: `src/benchmark-juliet.js`
- Modify: `src/benchmark-labeled.js`
- Create: `docs/benchmarks/dotnet-parser-fixtures.json`
- Test: `test/csharp-parser-integration.test.js`

**Interfaces:**
- Produces: `analyzeCSharpFile(source, options) -> { ast, complete, fallback, findingsContext, coverage }`.
- Coverage output reports eligible-file and discovered-method parse percentages overall and by dataset tier.

- [ ] **Step 1: Freeze coverage fixture manifest** with syntax fixtures, own .NET apps, eShop, WebGoat.NET, and Juliet C# revisions; hash exact inputs.
- [ ] **Step 2: Add failing integration tests** proving complete parse selects structural representation, incomplete parse invokes existing regex path, `.cshtml`/`.razor` always use regex, and fallback counts as unparsed.
- [ ] **Step 3: Implement** C# parser dispatch without changing existing rule semantics; expose parser coverage and fallback counts in benchmark reports.
- [ ] **Step 4: Verify** existing regression suite and supplied apps have zero finding regressions; calculate at least 95% complete method parsing by dataset and overall.
- [ ] **Step 5: Benchmark** fixed inputs against the pre-change engine commit; require parser scan time <=1.5× baseline and report file/method coverage.
- [ ] **Step 6: Commit** integration, frozen fixture manifest, tests, and baseline comparison.

### Task 7: Review and gate the evaluation/parser phase

**Files:**
- Create: `docs/benchmarks/dotnet-parser-phase-report.json`
- Modify: `docs/DOTNET-COVERAGE.md`

- [ ] **Step 1: Run** self-authored regression, Juliet unit scorer, and frozen coverage fixture scans at CLI default confidence.
- [ ] **Step 2: Record** per-tier metrics, parser coverage, fallback count, scan time, engine SHA, manifests, and any unresolved/missed gate.
- [ ] **Step 3: Confirm** misses prevent default behavior; if parser acceptance gates are missed, retain parser behind an explicit opt-in or do not ship.
- [ ] **Step 4: Commit** immutable phase report and documentation.

