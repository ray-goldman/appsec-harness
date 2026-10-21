.NET Taint Analysis and Independent Evaluation Design

## Purpose

Improve Kayfabe's .NET analysis beyond file-local regex taint while making benchmark claims independently verifiable. The work must improve cross-file recall without increasing false positives on the existing regression sets, and must report the limits of each evaluation tier rather than combining incomparable results.

## Evaluation independence and tiers

A dataset is **independently authored** only when every author has never seen Kayfabe's rules, its existing labeled corpus, its supplied benchmark applications, or its scorer before authoring and freezing the dataset. A Codex process operating in this repository does not meet that requirement. An independently authored dataset must be authored in a clean checkout containing only the written task specification; record the author or system, the exact materials visible during authoring, and the date. The clean checkout must not contain harness sources, benchmark labels, prior apps, or scoring code. If the author is a language model, also record the model identifier and its training cutoff, and the date Kayfabe's repository first became public; a model whose cutoff is after that date may have seen the harness and its set cannot be called independently authored.

Report results in three separate tiers; never aggregate their counts or headline scores:

1. **Self-authored regression** — Kayfabe's existing corpus and apps, plus new cases created by maintainers who know the rules. This tier detects regressions and supports development; it is not evidence of independent accuracy.
2. **Independently authored** — frozen applications authored under the isolation rule above. Keep source, labels, and scoring policy sealed from rule authors until the scheduled phase score.
3. **Third-party real code** — Juliet, WebGoat.NET, and sampled public repositories. Report benchmark-specific label provenance and adjudication; do not describe these as independently authored test apps. Within this tier, mark each dataset as **seen** (it has already informed a rule or analysis change) or **unseen**.

### Roles

- **Author** — writes the independently authored apps and their labels. Must meet the isolation rule above.
- **Custodian** — holds the sealed source, labels, and SHA-256 manifest, and releases them only for the scheduled phase score. May be a maintainer, provided they do not read the contents before the score.
- **Scorer** — runs the frozen scorer against the sealed set at the phase boundary. May be a maintainer; once a holdout is scored it is spent, so maintainers may read its per-label results afterwards, and the set moves to the development tier.

Only the author must be isolated from the harness. If that isolation cannot be arranged, label the proposed apps as self-authored regression data and do not claim a blind result.

### Authoring brief and label schema

The task specification given to an independent author must not leak rule knowledge. Write it at the level of application features and a CWE coverage list fixed in advance (for example, "an order history page; include CWE-639 and CWE-89 somewhere in the app"), not code patterns, sink names, or architectural hints that mirror Kayfabe's rules. Require a safe twin for every vulnerable label, so precision can be measured on the same constructs.

Every label must record: file, line range, CWE, polarity (vulnerable or safe), and a one-line rationale. For flows that cross methods or files, the label must also record the source location and the sink location; a finding counts when it is reported at the sink location, and the finding's reported path is recorded but not required to match exactly.

### Freeze and retirement

Before a phase score, publish a SHA-256 manifest for the exact source and label inputs, the scorer version, the engine commit SHA, and the scoring policy. Define and record the phase ship gates before tuning. Score a frozen holdout once for that phase. Any rule or analysis change informed by seeing its findings or results must be logged with the affected rules and rationale, and that holdout is retired to the development tier for subsequent phases. It cannot be presented as a fresh holdout again. Keep historical phase scores immutable and identify the dataset tier, phase, and engine commit in every report.

### Classification of existing datasets

Under these rules, the datasets already in use are classified as follows. Reports must use these labels from now on.

- **Own .NET apps, including those listed in `HELD-OUT.sha256`** — tier 1 (self-authored regression). They were written by the rule author and scored more than once; their earlier held-out numbers must not be presented as blind.
- **Juliet C# 1.3, both dev and held halves** — tier 3, seen, development use. The held half informed the CWE-329 scoping fix and is retired under the rule above.
- **dotnet/eShop and OWASP/WebGoat.NET** — tier 3, seen. Both informed rule changes. They may be used for precision adjudication, but must be reported as seen and must be excluded from the public-repository sample.

## Phase 0: evaluation protocol and baseline

Define label semantics, unit of analysis, duplicate handling, finding-to-label matching, per-CWE/per-rule reporting, confidence handling, and adjudication procedure before running the scanner on any sealed set. Include adjudication guidance and record disagreements.

**Juliet unit of analysis.** For single-file testcases the unit stays file × CWE × polarity. For multi-file testcases (variants with a letter suffix, such as 51a/51b, and the 81 bad/good split), the unit is the whole testcase: family plus variant number, covering all of its files. A testcase's bad unit is a true positive if a finding of the unit's CWE falls inside a bad region of any of its files; its good unit is a false positive under the same rule for good regions. Freeze the list of cross-file variants (22a/b, 51–54, 61, 66–68, 71–75, 81) in a manifest before measuring, and update the scorer to this policy before the Phase 2 baseline is taken.

**Confidence threshold.** Gates are evaluated at the CLI's default confidence threshold, which is currently `low` (every finding). Results at `medium` and above are reported alongside, so the cost of low-confidence findings stays visible, but do not decide a gate. If the CLI default changes, the gate threshold changes with it only at a phase boundary, before that phase's holdout score.

**WebGoat.NET.** Review the approximately 80 current findings and label each as true positive, false positive, or unresolved before using its results; then record missed known vulnerabilities separately. Report it as seen.

**Public repositories.** Document the sampling frame and selection criteria for 30–50 repositories (for example: ASP.NET application code rather than libraries, minimum activity and age, permissive license, no forks, no generated samples or templates), freeze the list and revisions before the first scan, and exclude eShop and WebGoat.NET. Adjudicate a stratified sample of approximately 150 findings, stratified by rule. Use two adjudicators per finding, record their agreement and how disagreements were resolved, and report per-rule estimates with their sample sizes. Do not call these estimates a census of all repository findings.

The initial ship gates are:

- Juliet cross-file testcases (per the unit above) achieve at least 60% recall, reported separately from the Juliet overall score. Juliet is a seen development dataset, so this gate measures development progress, not independent accuracy.
- The existing self-authored .NET development apps have zero false positives.
- The independently authored holdout is frozen and scored once at the designated phase boundary; it is not a tuning target after that score.
- The stratified real-repository sample has overall precision of at least 80%, computed with stratum weights proportional to each rule's finding count in the sampled repositories; the gate uses the lower bound of a 95% Wilson interval. Per-rule estimates are reported with their sample sizes and intervals but do not individually decide the gate.
- No phase may claim a false-positive reduction unless compared with the same labeled units and policy; report absolute FP counts and precision alongside recall.

If the independent author, adjudicated labels, or sample size is not available, mark the corresponding gate **not measured**, not passed. Gates may be revised only before a new phase begins and before its holdout score is seen.

**Missed gates.** A phase that misses a measured gate does not ship as default behavior. Its changes either ship behind an explicit opt-in flag, with the missed gate stated in the release notes, or do not ship.

## Phase 1: bounded C# structural parser

Implement a small structural parser in plain JavaScript without type resolution. The declared supported syntax is:

- Namespaces, classes, structs, interfaces, records, partial declarations, fields, properties, methods, constructors, attributes, and parameters.
- Blocks and statements: declarations, assignments, expression/return/throw statements, `if`/`else`, `switch` sections, `try`/`catch`/`finally`, loops, `break`/`continue`, and using statements/declarations.
- Expressions: identifiers and literals; calls; member and indexer access; object creation; unary/binary/conditional expressions; lambdas and local functions.
- Lexical forms: regular, verbatim (`@"..."`), interpolated (including nested braces and format specifiers), raw (`"""..."""`), and UTF-8 string literals; character literals; comments.
- Preprocessor directives: `#if`/`#elif`/`#else`/`#endif` must be tokenized and handled explicitly. All branches are parsed and analyzed, as the current scanner does; regions are recorded so evaluation policies that depend on them (Juliet's `OMITBAD`/`OMITGOOD`) keep working.

The parser must expose source spans and a statement/control-flow tree adequate to reason about assignment dominance and branch-local values, including early exits (`return`, `throw`, `break`, `continue`), `switch` section boundaries, and `try`/`catch`/`finally` edges. `goto` and unsafe code are unsupported. Unsupported or malformed syntax must not be silently treated as successfully parsed. For those files, retain the current regex analysis as a fail-closed compatibility fallback and report fallback use. `.cshtml` and `.razor` files are out of scope for the parser and stay on the regex path.

Publish parser coverage as both (a) percentage of eligible C# files with a complete parse and (b) percentage of discovered methods with a complete parse, counting fallback files/methods as unparsed. Show these metrics overall and by benchmark tier. Freeze a coverage fixture set before implementation begins: the supported-syntax fixtures, the own .NET apps, eShop, WebGoat.NET, and Juliet C#.

Acceptance requires:

- At least 95% of methods in the frozen coverage fixture set parse completely, reported per tier and per dataset.
- Visible coverage/fallback metrics in benchmark output.
- Zero regression-suite or supplied-app regressions.
- Scan time at most 1.5× the current scanner on the same fixed inputs. Phase 2's project-wide analysis is measured and budgeted separately.

A fallback must never make a coverage regression invisible.

## Phase 2: project-wide taint summaries

Build a project index of namespaces, classes, partial classes, methods, parameters, and fields. Resolve calls conservatively by method name and arity, adding receiver type where safely inferable. Receiver types for injected services are inferred through the chain field type → constructor parameter type → interface → dependency-injection registration. Resolve dependency-injection registrations for a single explicit implementation, with a unique-implementer fallback; ambiguous targets remain unresolved rather than guessed.

Use a versioned method-summary schema so later authorization analysis can consume the same index. Version 1 summaries record:

- parameter-to-return flow, parameter-to-sink-category flow, and parameter-to-field-write flow;
- source-to-return flow and source-to-field-write flow, by source category;
- per sink category, whether each flow passes through a sanitizer effective for that category (for example, HTML encoding neutralizes XSS but not SQL injection); flows are not sanitized for categories their sanitizer does not cover.

Propagate summaries to a bounded fixpoint with explicit depth, iteration, and cycle limits; expose truncation/unresolved-call counts in diagnostics. Findings should include the resolved caller/callee path.

The following call forms are not resolved in version 1 and count as unresolved: extension methods (whose receiver shifts arity), overloads with equal arity, calls relying on optional or named arguments, `params` arrays, virtual/override and interface dispatch with more than one implementation, delegates, and lambdas passed to LINQ or other higher-order APIs. Calls into a file that fell back to regex analysis produce no summary and also count as unresolved.

Confidence rules:

- A visible caller propagating known taint into the sink yields high confidence.
- A public method with no visible caller may produce a low-confidence finding, as in the current policy; do not silently promote it.
- If every resolved call site supplies constants for the relevant parameter, suppress the corresponding parameter-flow finding. This applies only to `private` methods and to `internal` methods in assemblies without `InternalsVisibleTo`; public and protected methods can have callers outside the analyzed code and are never suppressed this way.
- Ambiguous or unresolved calls cannot establish high-confidence taint, and a method with any unresolved call site cannot be suppressed by the constants rule.

Acceptance requires a controller-to-service-to-repository regression case, at least 60% recall on the pre-labeled Juliet cross-file testcases, and no increase in false positives on the same adjudicated Juliet units, self-authored apps, and any available labeled WebGoat/repository sample. Report recall and false positives together by CWE and confidence. Report Phase 2 scan time against the Phase 1 budget separately. Keep ordinary same-file findings stable unless an explicitly reviewed correction changes them.

## Phase 3: framework and authorization model

Extend the project model to collect MVC controllers/actions, Razor Pages, minimal API routes/groups, and hubs. Compute effective authorization from attributes and inheritance, `[AllowAnonymous]`, endpoint/group conventions (including `MapControllers().RequireAuthorization()` and group-level `RequireAuthorization`), global filters (`AuthorizeFilter` added to MVC options), and the configured fallback policy where statically visible. Flag state-changing endpoints (unsafe HTTP verbs) and administrative endpoints only when no effective policy is established. "Administrative" is a naming and route heuristic; report its findings and false positives separately from the verb-based check. Distinguish route-level policy from object-level authorization checks for IDOR analysis.

Add bounded middleware-order checks for authentication before authorization, CORS placement, and HTTPS/HSTS middleware, covering both minimal hosting and `Startup.Configure`. Add focused checks for login rate limiting, security headers/CSP, and anti-forgery on cookie-authenticated unsafe verbs. Extend data-layer and deserialization modeling to documented EF Core raw SQL wrappers, `string.Format` SQL construction, Dynamic LINQ, risky polymorphic/typeless deserialization settings, MessagePack typeless mode, and YamlDotNet. Model Razor/Blazor flows only where source spans and component/parameter relationships are supported; otherwise report coverage limits rather than guessing.

Every new check ships with a paired vulnerable/safe corpus case and is run against the adjudicated real-repository sample before it is enabled by default; report its findings and adjudicated false positives there.

Use the independently authored authorization labels for the phase gate: at least 70% recall with no regression on previously measured tiers. Report false positives and unresolved framework constructs. Do not tune against an already scored holdout; retire it to development if its results inform a fix.

## Phase 4: opt-in stored data and documented coverage gaps

Keep database/file-read flows behind an explicit stored-data option with distinct rule IDs for stored XSS and second-order SQL injection and low default confidence. Evaluate their incremental recall and precision against the adjudicated real-repository sample before considering a default change. Document deliberate non-detections, including the four currently zero-coverage Juliet categories and the rationale for handling CWE-209 responses, `new Random()`, plain-HTTP URLs/CWE-319, and CWE-506.

## Phase 5: NuGet advisories and triage evidence

Verify every existing curated NuGet advisory against authoritative GHSA/NVD/OSV records and record source, identifier, affected range, verification date, and provenance. An unverified or unverifiable advisory must not ship as authoritative detection data; keep it explicitly quarantined or omit it. Create an offline snapshot with pinned provenance and a visible snapshot date. Building the snapshot is a maintainer step that uses the network; scans read only the snapshot and keep within the network rules in AGENTS.md. Read direct and transitive dependency data from supported lock files and `project.assets.json`; add reachability-lite only when vulnerable API references can be established conservatively.

Extend triage items with the project call path and, when known, route authorization context and effective policy. Evaluate triage verdict accuracy against adjudicated labels, separately reporting real-finding dismissal and safe-code confirmation rates; scanner accuracy and agent triage accuracy must remain distinct metrics. For each triage evaluation, pin and record the model identifier, prompt version, and sampling settings; run each item at least three times and report variance; and keep labels, adjudication notes, and scorer output out of the agent's context.

## Delivery, sequencing, and non-goals

Keep the existing corpus as the regression suite. Avoid rule changes targeted at individual Juliet examples; new behavior must follow general syntax, flow, or framework semantics and include paired safe/vulnerable cases. Keep benchmark source/labels and reports tiered so that holdout data cannot leak into development scoring. Deliver each phase with its manifest/provenance, engine commit SHA, score report, parser coverage where applicable, and a review of false-positive changes.

Recruiting an isolated author for the independently authored set is on the critical path. Phase 1 consumes no holdout and may proceed in parallel with Phase 0; the Phase 0 protocol, label schema, and the updated Juliet scorer must be frozen before the Phase 2 baseline is taken.

This design does not promise full C# language parsing, whole-program type resolution, complete framework configuration evaluation, or sound static analysis. Unsupported syntax and ambiguous call targets remain explicit limitations.