# Planned improvements

The existing corpus was written alongside the rules. Its precision and recall describe regression coverage, not independent detection accuracy. Keep that suite, and measure detection on external labels before expanding the engine.

## 1. Independent accuracy measurements — in progress

- Start with an OWASP Benchmark Java runner using the upstream expected-results CSV. Report TP, FP, TN, FN, recall (true-positive rate), false-positive rate, and precision per CWE.
- Record dataset revision, input hashes, scanner configuration, and scoring policy. Include unsupported CWEs and missed cases in the denominator. Publish low scores without tuning rules to this first measurement.
- Add Juliet and selected NIST SARD datasets, with adapters for their labels. Define scoring units before running: good and bad functions can coexist in one file, so file-level scoring alone is insufficient.
- Build a CVE-fix corpus from real fix commits for vulnerabilities in `CVE-CATALOG.md`. Record upstream repository, parent and fix SHAs, changed vulnerable paths, expected CWE, and review evidence. Measure detection on the parent and silence on the fix.
- Preserve `selftest` as the regression suite. Keep regression, independent synthetic benchmark, and real CVE-fix results separate.

Completed measurements:

- [OWASP Java](BENCHMARKS.md): all 2,740 labeled cases; 40.35% recall and 23.70% FPR.
- [Juliet Java 1.3](JULIET-SARD.md): all 28,881 upstream testcases, represented by 57,649 good/bad units across 112 CWEs; 8.34% recall and 8.14% FPR under the documented label-correction policy.
- [NIST SARD suite 115](JULIET-SARD.md): all 20 vulnerable PHP locations; 50% recall. No safe labels, so FPR is undefined.
- [Real CVE-fix corpus](CVE-FIX-CORPUS.md): eight curated parent/fix pairs; one parent hit, one fixed-side alert, and zero successful complete pairs.

The [detection-gap report](DETECTION-GAPS.md) links all three new baselines and records the misses, false positives, dataset limits, and follow-up work. Priority 1 remains open for additional SARD datasets with negative labels, broader CVE-catalog coverage, and more precise CVE location/context scoring. Detection rules were not tuned in this measurement change.

Subsequent [precision work](PRECISION-IMPROVEMENTS.md) adds bounded Java constant
analysis, PHP request-source evidence, and separate CVE source-region scoring.
It preserves the original baselines. The next [Java scope and branch pass](JAVA-SCOPE-BRANCHES.md)
adds lexical binding and bounded constant conditions, removing another 278
Juliet and 13 OWASP false positives without losing detected true-positive cases.
The [helper and sanitizer pass](JAVA-HELPERS-SANITIZERS.md) adds bounded Java
method summaries and HTML text proofs, with two further independent reviews.
The [formatting-array pass](JAVA-FORMAT-ARRAYS.md) supports single-use local
scalar arrays and rejects initializer side effects, fixing the newly exposed
OWASP case. The [supplied apps](SUPPLIED-APPS.md) provide a separate provisional
baseline and concrete helper/guard candidates for future work.
The [JavaScript/Python helper pass](SCRIPT-HELPERS.md) reviews 11 safe labels,
adds bounded numeric helper and Flask hostname-guard proofs, and reduces
supplied-label FPs from 16 to 14. Both corrections are Python cases; JavaScript
computed properties and shared exports remain unsupported. The two review
passes and their conservative fixes are recorded separately from accuracy scores.
Remaining priorities are held-out accuracy data, broader Java call and collection flow, negative SARD examples, and
mechanism-specific detection for the seven still-missed CVE parents.

## 2. Parsing and cross-file taint

- Keep the regex engine as the default.
- Add an optional, vendored tree-sitter layer for AST-based rules and a call graph.
- Follow taint through controller → service → repository calls, with explicit limits for unresolved calls and dynamic dispatch.
- Document the optional layer's dependencies, supported grammars, distribution licenses, and update process.

## 3. Supply-chain data

- Test the existing `--osv` integration against the live service. The supplied improvement proposal reports that earlier network testing was blocked.
- Add an offline OSV/GHSA snapshot for disconnected runs. Show its date and provenance in reports, including when it is stale.
- Distinguish packages imported by application code from packages merely listed in a lockfile. Treat this as basic reachability evidence, not proof of exploitability.
- Add CycloneDX SBOM output.
- Define an update process for curated advisories; a fixed catalog will become stale.

## 4. Triage evaluation

- Evaluate reviewer decisions, beyond validating the shape and location of evidence.
- Use independently labeled vulnerabilities and safe look-alikes with Claude Code and Codex. Record model/version, prompt, dataset revision, and repeated runs.
- Measure false dismissals and false confirmations separately.
- Include prompt-injection attempts in comments, strings, and README files. Quarantining agent configuration does not cover those surfaces.

## 5. Pull-request workflow

- Add changed-file scanning and PR annotations. State which context is lost when only changed files are scanned.
- Improve fingerprint stability across code moves and refactors, and measure collisions.
- Ship a GitHub Action and pre-commit hook with documented inputs, permissions, and exit behavior.

## 6. Follow-up work

- Confirm relative MCP path resolution in Codex; retain absolute-path registration as an alternative.
- Add Rust, Swift, Dart, Helm, and CloudFormation coverage with paired regression cases.
- Add an opt-in DAST/fuzzer integration that accepts only an explicitly allow-listed staging URL and defined scope.
- Choose a distribution license before public sharing. The current package is `UNLICENSED`; the GitHub repository is private.
- Add a maintainer and CWE/CVE references for each rule. Track false positives by rule and demote noisy rules using measured evidence.
