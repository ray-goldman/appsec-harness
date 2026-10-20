# Java helper calls and sanitizer handling implementation plan

> **For agentic workers:** Use `superpowers:executing-plans` for sequential implementation, with two fresh independent reviewers before opening the PR. Track the steps below as they complete.

**Goal:** Reduce Java false positives by proving helper-call values and tracking context-specific encoding, while preserving detected vulnerabilities.

**Architecture:** Extend the existing bounded Java proof with method summaries, then a narrowly resolved source index for static calls. Track encoding as a property of a particular value at a particular sink, separately from constantness and attacker influence. Unsupported syntax, ambiguous dispatch and exhausted budgets retain findings.

**Tech stack:** Node.js >=20, CommonJS, built-ins only; static analysis only.

**Spec:** The user's request to start with Java helper calls and sanitizer handling, rerun all benchmarks and complete two review passes before a PR; the design decisions below make that request concrete.

**Status:** User approved implementation. Helper tests and implementation are in progress; both review passes and final measurements follow.

**Starting point:** merged `main` at `4fae4d9ae0113b86779320dd4c7d6896c0cefc64`. Planning branch: `codex/java-helper-sanitizer-precision`.

## What the examination found

Counts below come from the completed `scope-branches-*` measurements, not a new scanner run.

| Dataset | SQL FP | Command FP | XSS FP | Redirect FP | Other FP | Total FP |
|---|---:|---:|---:|---:|---:|---:|
| Juliet | 956 | 228 | 0 | 8 | 34 crypto | 1,226 |
| OWASP | 116 | 72 | 105 | 0 | 8 path | 301 |

Juliet retains 2,410 TP; OWASP retains 571 TP. Counts by rule can overlap within a case, so they must not be added as if they were distinct cases.

### Helper opportunities

- Juliet variants `41` and `42` account for **128 remaining FP units**: 100 SQL, 24 command and four redirect. Representative source inspection confirms same-class argument passing (`41`) and return values (`42`). This is a candidate pool, not a prediction that all 128 disappear.
- In `CWE78_OS_Command_Injection__Environment_42.java`, a private helper returns a literal, but the caller's sink cannot use that fact.
- In variant `41`, a private sink helper receives only a literal from its modeled caller. Its formal parameter currently remains unknown. A helper with any unsafe or unresolved caller must retain its finding.
- **49 of 72 OWASP command FP files** contain `getOSCommandString`. Reading the helper shows that its return combines a parameter with literal prefixes selected by OS. With a constant argument, every return is independent of request data. The OS check itself does not need to be evaluated. Other unresolved values at the sink may still prevent suppression.
- Public cross-file sink helpers, object fields, containers, inheritance and reflection account for many remaining Juliet flows. Seeing one safe call is insufficient to declare a public helper safe.

### Sanitizer opportunities and hazards

- Among OWASP's 105 XSS FP files, 14 contain Spring `HtmlUtils.htmlEscape`, 23 contain `encodeForHTML`, and six contain `escapeHtml`. These are overlapping whole-file search markers; some encoders occur in helpers or unrelated output. They are not verified recoverable counts.
- `BenchmarkTest00278` assigns `HtmlUtils.htmlEscape(param)` to `bar`, then prints `bar` on a later line. The rule's `notLine` check does not connect these operations.
- `BenchmarkTest01255` returns Commons `escapeHtml(param)` through an inner-class helper. That also requires receiver/method resolution and is outside the initial helper subset.
- `BenchmarkTest00281` prints a constant selected by a ternary through `printf`. XSS currently does not use the local constant proof, and formatted output needs argument-position handling.
- `src/languages.js` has a file-wide tainted-name map and a generic sanitizer-name regex. `src/engine.js` also skips wrapped arguments, while `JAVA-XSS-001` skips a whole window containing an encoder name. These mechanisms cannot establish that the actual sink value is protected in its actual context.
- An HTML-encoded value remains attacker-influenced and can still be unsafe in SQL, commands, JavaScript or URLs. Sanitizer facts must not become universal taint removal.

### Another measured gap to keep visible

Juliet has 44 FP units with `JAVA-SQLI-002`. A sampled constant SQL expression in `sqlStatement.execute(...)` illustrates a receiver-recognition gap: the sink pattern does not recognize this receiver name, so the assembly proof cannot cover the call. Record this separately. If addressed in this change, require a resolved JDBC receiver and unsafe controls; do not broaden every `.execute()` into a SQL call.

## Approach and scope

### Recommended: bounded summaries plus contextual encoding

Implement same-class helper returns first, then private helper parameters, then exact static source calls across files. Follow with value-specific HTML-text encoding and the servlet-output cases the proof can actually establish.

Two alternatives were considered:

- More helper/encoder name allow-lists would be cheaper but would trust custom methods with misleading names and unrelated nearby calls.
- A complete Java AST, call graph and points-to engine would support more flows, but it is a larger project and changes the dependency/design constraints. Keep that on the roadmap.

The first PR supports a deliberately restricted call subset. It does not promise to remove every helper-related warning.

### Value and call contracts

Use a shared `ValueFact` representation:

```text
{
  known: boolean,
  constant?: string | number | boolean,
  dependencies: number[],       // formal parameter indices, not variable names
  encodings: ["html-text"],     // empty unless specifically proven
  evidence: [{ file, startLine, endLine }]
}
```

`known: false` is unknown, even if the other arrays are empty. `known: true` with no dependencies proves no external value contributes to the result; it does not prove one exact value. Distinct literal return alternatives can therefore be safe without pretending they are equal. A concrete `constant` requires the existing typed evaluator to establish the value.

Join every reachable return: union dependencies, intersect encoding guarantees, retain a concrete value only if every return agrees. Unresolved return behavior produces unknown. Keep dependencies after encoding; encoding changes allowed output contexts, not input provenance.

Resolve calls by owning class, method, argument count and supported parameter types. Initially accept unambiguous private same-class calls and static calls whose source target is exact. Reject overload ambiguity, virtual/interface dispatch, varargs, reflection, method references, recursion, native methods and unknown external implementations.

For a parameter used inside a **private** helper, suppression requires complete enumeration of its callers in the owning class, all arguments proven safe, and no unsupported reference/escape mechanism. Zero observed callers is unknown. Public/protected/package-visible sink helpers keep unknown external callers. Static return summaries remain usable at individual call sites regardless of their callers elsewhere.

Array/object parameters, field reads/writes and escaping mutable state are outside the initial summary subset. Unknown side effects invalidate affected facts. A known call must never invalidate the existing all-writes, scope, Unicode or branch checks.

### Context and encoding contracts

Initial library models: exact Spring `org.springframework.web.util.HtmlUtils.htmlEscape(String)`, OWASP Java Encoder `org.owasp.encoder.Encode.forHtml` / `forHtmlContent`, and Commons HTML-escape methods where resolution and API contract are established. Resolve qualified names or explicit imports; reject local type/method shadowing and ambiguous imports.

Treat these as `html-text` facts only in this phase. Do not infer safety for script/style text, event handlers, URLs, dynamic tag/attribute names, unquoted attributes, SQL, shell commands, redirects or paths. ESAPI's configurable encoder needs a separately verified provider/configuration model; the name `ESAPI.encoder()` alone is insufficient.

At an HTML sink, prove every dynamic piece has the required property. Concatenating raw input or decoding after encoding removes that guarantee. Reassignment and joins include every relevant write. An unrelated sanitizer call on the same line protects nothing.

Model bounded output context for recognized servlet response entry methods: start in document text only when the receiver and method contract are known; process preceding writes in order. Literal fragments may establish text context. Dynamic markup, unresolved writer aliases/calls, branching that disagrees on context, or an unknown earlier write make context unknown and retain the warning. A standalone fragment is insufficient if earlier output opened a script or attribute.

For `printf`, distinguish an optional Locale argument, the format string and substituted values. Initially support constant formats and explicit immutable scalar arguments only. Escaping the format string does not escape substitutions. Unknown vararg arrays and unsupported formats retain findings.

## Global constraints and limits

- Zero runtime dependencies; never compile or execute benchmark/project code.
- Preserve the original baselines, the prior precision reports and the `scope-branches-*` reports.
- Preserve existing Java method/expression bounds. New call expansion: depth **4**, **32** distinct methods and **10,000** work steps per proof; cycles return unknown.
- A method summary supports at most **16** parameters, **32** returns and **64** call sites. Larger methods remain unknown.
- Project source index: at most **50,000** Java files and **100 MiB** of retained source. Exceeding the cap disables cross-file proofs; independent complete-file local proofs may still run. Excluded, unreadable or truncated input cannot be treated as proof of no competing declaration/caller.
- Exact cross-file resolution requires complete class metadata, unique qualified names, and source confined to files accepted by the existing walker. No following symlinks, separate network access or broad disk search.
- Cap recorded proof evidence at **32** locations. Cache summaries by source identity, method identity and fact inputs; do not reuse a safe result across different arguments.
- Keep Kotlin and other languages' behavior separate. Changes to shared helpers must have explicit Java-only options and compatibility tests.
- Never whitelist benchmark names, `good`/`bad` methods, case IDs or fixture layouts.

## Implementation tasks

### 1. Establish the case inventory and unsafe controls

**Files:** create `test/java-helper-precision.test.js`, `test/java-sanitizer-precision.test.js`; update `package.json`; later add paired `corpus/java-helper-precision/` and `corpus/java-sanitizer-precision/`.

- [ ] Save a reproducible case inventory from the existing full reports: case ID, CWE, finding locations, likely cause and inspected evidence. Keep category markers separate from verified causes.
- [ ] Add safe/unsafe pairs with neutral names and different constants from the benchmarks: constant-return helper versus request-return helper; private sink with only constant callers versus one unsafe caller; escaped alias versus mixed raw output.
- [ ] Run the focused tests and record the expected failures before implementation. Existing unsafe tests must already assert retained findings.
- [ ] Add non-benchmark controls for every failure mode in Review Focus below. Do not tune benchmark labels.

### 2. Add same-class helper summaries

**Files:** create `src/java-methods.js` and `src/java-summaries.js`; extend `src/java-constants.js` and, if needed, `src/java-branches.js`; tests from task 1.

**Interfaces:**

- `indexJavaFile({ file, raw, code }, limits) -> JavaFileIndex`
- `summarizeJavaCall({ index, callerId, callOffset, argumentFacts, budget }) -> ValueFact`
- `privateParameterFact({ index, methodId, parameterIndex, budget }) -> ValueFact`

- [ ] Extract method/class ownership and offsets with bounded structural parsing; return unsupported status instead of guessing.
- [ ] Implement literal/parameter/concatenation returns, all-return joins and safe argument substitution.
- [ ] Connect return summaries to the existing scope/constant proof; cover nested helper chains within the explicit budget.
- [ ] Add private-parameter proof only after complete caller resolution. Prove safe and unsafe callers independently; retain a helper finding if any caller is unknown.
- [ ] Verify overloads, same names in different classes, recursion, unknown calls, mutable parameters, later writes and Unicode escapes retain warnings.
- [ ] Run focused tests, `npm test` and selftest. Commit this independently testable unit.

### 3. Resolve narrowly supported static helpers across files

**Files:** create `src/java-project.js`; update `src/engine.js`, `src/java-summaries.js`; extend helper tests.

**Interfaces:**

- `buildJavaProjectIndex(files, limits) -> JavaProjectIndex`
- `resolveJavaStaticCall({ project, callerFile, owner, name, argumentTypes }) -> MethodTarget | null`

- [ ] Build the bounded index from the same accepted source set used by `scan`; preserve raw text for unsupported-syntax checks.
- [ ] Resolve fully qualified and explicitly imported static calls to unique source methods. Never treat a missing definition as safe.
- [ ] Prove the generic shape “literal prefix plus parameter on every return,” including unknown guards selecting between safe alternatives. Add a renamed two-file fixture rather than special-casing `Utils.getOSCommandString`.
- [ ] Test duplicate qualified classes, missing files, truncation, import ambiguity, unsafe second return, cycles and cross-file cache contamination.
- [ ] Test that a public sink helper remains a finding even when its one observed caller is safe.
- [ ] Run focused tests, full tests and selftest; commit.

### 4. Track sanitizer results to the correct sink

**Files:** create `src/java-sanitizers.js`; extend `src/java-methods.js`, `src/java-summaries.js`, `src/engine.js`, `src/rules/java.js`; update Java-only behavior in `src/languages.js`; extend sanitizer tests.

**Interfaces:**

- `javaEncodingFact({ resolvedCall, argumentFacts }) -> ValueFact`
- `javaOutputContext({ index, methodId, sinkOffset, receiver }) -> "html-text" | "unknown"`
- `proveJavaOutput({ expression, valueFacts, outputContext, callKind }) -> boolean`
- `analyzeTaint(codeLines, lang, options = {})`: add `options.genericSanitizers`; default preserves existing non-Java behavior.

- [ ] Add exact supported encoder models with API references and shadowing checks. Preserve attacker dependencies in encoded facts.
- [ ] Track encoded aliases, helper returns, reassignment and branch joins. Apply the existing constant proof to supported output expressions.
- [ ] Replace Java XSS whole-window exclusions and generic wrapper shortcuts with proof of the actual argument and context. Ensure earlier generic taint handling cannot erase unsafe Java XSS candidates before this step.
- [ ] Cover plain output, literal HTML text fragments and supported `printf` overloads. Retain ambiguous contexts and mutable vararg arrays.
- [ ] Assert warnings for wrong-context encoding, encoded format plus raw substitution, encode-then-decode, fake sanitizer names and two sinks on one line where only one is safe.
- [ ] Inspect any newly exposed findings caused by removing old shortcuts; document real detection gains and benchmark disagreements separately.
- [ ] Add paired corpus cases; run focused tests, full tests and selftest; commit.

### 5. Two independent review-and-improve passes

- [ ] **Pass 1:** a fresh reviewer examines call resolution, all callers/returns, mutable state, Java semantics, and actual sanitizer-to-sink flow. Reproduce every finding, fix with a regression, then have the reviewer verify the fixes.
- [ ] **Pass 2:** a different fresh reviewer examines the whole change for unknown-path suppression, shared-state contamination, unsafe encodings, adversarial source, resource limits and benchmark overfitting. Fix findings and obtain independent verification.
- [ ] Neither reviewer may accept a safe result based on a helper's name, a “good” label, or the presence of any sanitizer elsewhere in the window.
- [ ] Record findings, fixes, commands and remaining limitations. No unresolved issue that can hide a real finding may reach the PR.

### 6. Freeze, measure, compare and publish

- [ ] Freeze scanner sources after review fixes. Run `npm test` and `node bin/appsec.js selftest`.
- [ ] Run all four benchmarks, writing **new** `helper-sanitizer-*` output directories:

```sh
node bin/appsec.js benchmark owasp-java appsec-out/benchmarks/owasp-java --out appsec-reports/benchmarks/helper-sanitizer-owasp
node bin/appsec.js benchmark juliet-java appsec-out/benchmarks/juliet-java-1.3/Java --out appsec-reports/benchmarks/helper-sanitizer-juliet
node bin/appsec.js benchmark sard appsec-out/benchmarks/sard-115 --out appsec-reports/benchmarks/helper-sanitizer-sard
node bin/appsec.js benchmark cve-fixes appsec-out/cve-downloaded --out appsec-reports/benchmarks/helper-sanitizer-cve
```

- [ ] Compare every case to `scope-branches-*`, including both CVE revisions and both CVE policies. Verify identical input, label, annotation and policy hashes and one final scanner hash.
- [ ] Report TP/FP/TN/FN, per-CWE changes, corrected FP IDs, lost TP IDs, new FP IDs and scan duration. Aggregate improvements cannot conceal individual regressions.
- [ ] Acceptance: fewer FP overall in the targeted suites, **zero lost previously detected TP cases**, passing regression pairs and no unexplained new FP. Target zero new FP; if fixing an unsafe old shortcut exposes a disputed safe label, retain the warning and document the case explicitly rather than changing labels or silently excluding it.
- [ ] Preserve SARD's undefined FPR and distinguish the historical CVE 0/8 policy from the localized 1/8 policy. Do not forecast improvements to these corpora.
- [ ] If source changes after measurement, rerun affected review checks and all four final measurements on the final source hash.
- [ ] Write `docs/JAVA-HELPERS-SANITIZERS.md`, new aggregate JSON and a case-transition comparison. State that the suites are development data and provide remaining gaps.
- [ ] Check the complete diff and historical-report preservation, commit, push the new branch and open a PR against `main`. Attach it to this chat. Do not merge automatically.

## Review focus

Each item below belongs in the task 1 controls and the owning implementation task:

1. **Safe and unsafe callers share a helper:** a safe observed caller must not hide the unsafe call or assume no external callers.
2. **Misresolved calls:** overloads, shadowed library names, duplicate classes and virtual dispatch must produce unknown.
3. **Wrong output context:** HTML encoding cannot protect a script, URL, SQL expression or shell command; prior output can change the context.
4. **Partial encoding:** one encoded operand, format string, branch or nearby call cannot protect raw data elsewhere in the expression.
5. **Resource and semantic escapes:** recursion, budget exhaustion, cache reuse, mutation, Unicode preprocessing and incomplete scans must retain warnings.

## Deferred work

General virtual dispatch, reflection, mutable object fields, collections, inner-class captures, public sink caller closure, full prepared-statement object modeling and cross-file taint beyond this restricted call subset require broader analysis. The 34 Juliet crypto label disagreements remain visible. Further SARD negative datasets and genuinely held-out projects are still needed.

## References and evidence

- Current results: [Java scope and branches](../../JAVA-SCOPE-BRANCHES.md).
- Existing benchmark JSON: `appsec-reports/benchmarks/scope-branches-{owasp,juliet,sard,cve}/benchmark.json` (local generated reports).
- [Spring HtmlUtils API](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/web/util/HtmlUtils.html) documents HTML escaping.
- [OWASP XSS prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) explains why encoding must match the output context.
- [OWASP Java Encoder](https://owasp.org/www-project-java-encoder/) provides distinct encoding APIs by context.

## Plan self-review

The plan covers the requested helper-first order, sanitizer handling, safe/unsafe controls, both independent review passes and all four benchmark reruns. It separates return summaries from the stronger claim needed to suppress findings inside a callee. Candidate counts are explicitly not promised gains. The next action is task 1; no scanner behavior has changed during this investigation.

## Execution ledger

- User approved this plan and sequential implementation on the prepared feature branch.
- Pre-flight: helper summaries feed the existing local proof; sanitizer facts will use the same method ownership and source resolution. Preserve all existing unknown fallbacks.
- Using the prepared checkout and branch retains the downloaded benchmark inputs and the prior comparison reports. No additional worktree is needed for this sequential implementation.
- Task 1: added helper safe/unsafe controls before implementation; focused red run pending.
- Tasks 1–3: helper red run failed on four expected safe cases. Bounded same-class summaries, private caller checks and exact static source resolution now pass 11 helper test groups. Receiver shadowing and unsupported overloads were caught red→green by added controls. Full suite: 124/124 before the new paired helper corpus.
- Implementation detail: existing local proof is reused through `valueAt` rather than duplicating its lexical binding and mutation logic. Method facts travel with explicit argument state and a shared expansion budget.
