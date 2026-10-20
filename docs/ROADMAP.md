# Planned improvements

The existing corpus was written alongside the rules. Its precision and recall describe regression coverage, not independent detection accuracy. Keep that suite, and measure detection on external labels before expanding the engine.

## 1. Independent accuracy measurements — in progress

- Start with an OWASP Benchmark Java runner using the upstream expected-results CSV. Report TP, FP, TN, FN, recall (true-positive rate), false-positive rate, and precision per CWE.
- Record dataset revision, input hashes, scanner configuration, and scoring policy. Include unsupported CWEs and missed cases in the denominator. Publish low scores without tuning rules to this first measurement.
- Add Juliet and selected NIST SARD datasets, with adapters for their labels. Define scoring units before running: good and bad functions can coexist in one file, so file-level scoring alone is insufficient.
- Build a CVE-fix corpus from real fix commits for vulnerabilities in `CVE-CATALOG.md`. Record upstream repository, parent and fix SHAs, changed vulnerable paths, expected CWE, and review evidence. Measure detection on the parent and silence on the fix.
- Preserve `selftest` as the regression suite. Keep regression, independent synthetic benchmark, and real CVE-fix results separate.

First deliverable: the OWASP Java adapter and a reproducible baseline. Juliet/SARD adapters and the CVE-fix corpus remain subsequent work.

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
