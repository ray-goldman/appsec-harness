# Workflow environment boundary and remaining supplied findings

The supplied-app scorer now reports **12 false-positive labels, down from 13**.
The corrected case is `infra-mixed/.github/workflows/ci.yml:29` (label marker at line 26),
`gha-env-indirection`. All 81 detected vulnerable labels remain detected.
Inputs, labels, matching policy and scorer are unchanged.

## Final measurements

| Dataset / policy | Cases | TP | FP before → after | TN after | FN |
|---|---:|---:|---:|---:|---:|
| OWASP Java 1.2 | 2,740 | 571 | 289 → 289 | 1,036 | 844 |
| Juliet Java 1.3 | 57,649 | 2,410 | 1,172 → 1,172 | 27,596 | 26,471 |
| SARD 115 | 20 | 10 | 0 → 0 | 0 | 10 |
| CVE historical file+CWE | 16 | 1 | 1 → 1 | 7 | 7 |
| Supplied application labels | 227 | 81 | 13 → 12 | 78 | 56 |

Case-by-case comparison found one supplied `fp->tn` transition, no lost true
positives and no new false positives. Every external case outcome is unchanged.
Supplied FPR falls from **14.44% to 13.33%** and precision rises from **86.17%
to 87.10%**; recall remains **59.12%**. These supplied labels are unadjudicated,
not independent production accuracy evidence. The 54 manifest labels remain
unscored; unmatched findings remain unclassified.

Historical CVE scoring remains **0/8 complete pairs**. The separate localized
policy remains **1/8**, with TP=1, FP=0, TN=8, FN=7. SARD has no safe labels,
so its FPR is undefined.

Evidence: [case comparison](benchmarks/workflow-env-comparison.json),
[OWASP](benchmarks/owasp-java-1.2-workflow-env.json),
[Juliet](benchmarks/juliet-java-1.3-workflow-env.json),
[SARD](benchmarks/sard-115-workflow-env.json),
[CVE](benchmarks/cve-fixes-workflow-env.json), and
[supplied apps](benchmarks/supplied-apps-workflow-env.json).

All final runs used source SHA-256
`0eb0b8d266a2e9adece24cdd961637c14f91ac5e06525c7f3c0b096d18c1a24e`,
on October 20, 2026, with Node v24.16.0 on Windows. Timings are recorded but
are not a controlled performance comparison.

## What changed

`GHA-INJ-001` tracked the indentation of the sequence dash in `- run:`.
The sibling `env:` key is farther right than that dash, so its values were
mistakenly treated as part of the script. The rule now tracks the column of
the `run` mapping key. A sibling key ends the script scalar; more deeply
indented script content remains eligible for findings.

This fixes a boundary error in the existing line-based YAML rule. It does not
add a complete YAML parser or broaden the rule's supported expression syntax.
The new paired corpus case uses a run-first step and passes event data through
an environment variable in the fixed variant. No supplied application was edited.

## Review of all 13 starting labels

These are findings attached to user-supplied `safe` labels. The label alone does
not prove that a finding is wrong. The table records static evidence and the
reason for retaining each remaining warning; it does not claim exploitability.
Paths are relative to the named supplied application; line numbers identify sinks.

| App / file:line | Label | Assessment and next step |
|---|---|---|
| infra-mixed / .github/workflows/ci.yml:29 | gha-env-indirection | Resolved: the event expression is an environment value, outside `run`. Quoted shell expansion is the intended safe pattern. |
| go-api / main.go:57 | exec-argv-validated | A fixed `ping` program receives separate arguments and the hostname has a regex guard. The existing rule also warns about attacker-controlled arguments but assigns only CWE-78. Separate shell injection from CWE-88 argument injection before suppressing this label; its guard permits leading hyphens and there is no `--` separator. |
| go-api / main.go:71 | filepath-base | `filepath.Base` is assigned to a variable before `filepath.Join`; the rule only recognizes it on the sink line. A scoped, binding-aware Go value model is the next implementation candidate. Establish lexical path guarantees separately from filesystem/symlink assumptions. |
| go-api / main.go:89 | ssrf-host-pinned | Scheme and host are checked before `http.Get`. The snippet provides no redirect restriction or custom client policy. An initial-host guard alone cannot establish the destination of later requests. |
| java-bank / src/main/java/bank/UtilController.java:30 | normalize-startswith | `ROOT.resolve(file).normalize()` is checked with `Path.startsWith(ROOT)` before reading. This is a candidate for a scoped Java path-containment proof that follows the same value and guard; filesystem symlink behavior remains a separate assumption. No such proof is added in this pass. |
| node-shop / src/routes/files.js:29 | ssrf-allowlist | URL scheme and hostname are checked, but the axios call supplies no redirect policy. Retain until redirect behavior and the client configuration are modeled. |
| node-shop / src/routes/redirect.js:12 | relative-only-redirect | The local string must start with `/`, exclude `//` at the beginning and exclude backslashes; otherwise it becomes `/`. Candidate for a redirect-specific proof, but URL normalization/control-character behavior and the response API must be checked before calling it safe. |
| py-notes / app.py:108 | ssrf-allowlist | Parses and checks the initial URL, then requests the original string. No redirect restriction is supplied. Needs both parse/use consistency and redirect handling. |
| ts-react-portal / pages/api/proxy.ts:18 | nextapi-ssrf-allowlist | Checks the initial URL and calls `fetch` without a redirect restriction. Needs redirect handling; the optional JavaScript parser also does not parse TypeScript. |
| xfile-lab / js/routes.js:38 | real-shell-quote-helper | The helper quotes a POSIX argument, while the call provides no shell/platform restriction. Cross-file binding/effect checks and an explicit shell contract are required. |
| xfile-lab / js/routes.js:45 | validated-by-guard-helper | The helper checks `String(h)` and then the caller concatenates the original value. No primitive-string guarantee is established; the regex also uses a final `$` anchor. The narrower proof from PR #10 does not apply. |
| xfile-lab / js/routes.js:50 | constant-from-config | Config fields are literal strings, but the object is mutable and the route imports unresolved `./db`. A per-binding effect analysis would be needed to avoid requiring a closed project; merely accepting literal initializers is insufficient. |
| xfile-lab / py/views.py:38 | shlex-quote-helper | The helper calls `shlex.quote`, but `shell=True` has no explicit shell/platform contract. Retain pending a platform-aware command proof and imported-helper identity checks. |

The last pass measured no reduction because its new proofs required a narrower
source shape than these supplied callers: primitive-string guards, a closed
import graph and unmodified config ownership. This pass started from the actual
remaining findings and corrected a directly observed parser error instead.

## Next priorities

1. Model Go `filepath.Base` through a local variable, including reassignment,
   shadowing, aliases and parent/dot results. Keep filesystem effects explicit.
2. Model Java normalized `Path` containment through a dominating rejecting guard.
   Test mutation and alternate paths before adding a suppression.
3. Separate command/argument injection and document the scorer implications.
   A CWE taxonomy correction must not be presented as a newly proven safe case.
4. Investigate URL/redirect semantics and platform-dependent shell quoting before
   widening helper suppressions. Keep disputed labels unchanged until adjudicated.

## Verification

The boundary regression failed before the change and passed afterward. Tests
cover inline scripts, literal/folded scalars, explicit indentation indicators,
multiline plain scalars, ordinary mapping keys and extra spaces after the dash.
Existing multiline `script:` detection is checked too. Target source was only
read/scanned; no target code, builds, dependency installs or workflows ran.

All **185 tests** and **155 paired corpus cases** pass locally.

Two independent static review passes found no code issues. The second found
two documentation reference errors (marker versus expression line, and an
incomplete Java path); both were corrected. All benchmark runs and the
comparison passed against the reviewed source.

## Reproduction

```text
npm test
npm run selftest
node bin/kayfabe.js benchmark owasp-java appsec-out/benchmarks/owasp-java --out appsec-reports/benchmarks/workflow-env-owasp
node bin/kayfabe.js benchmark juliet-java appsec-out/benchmarks/juliet-java-1.3/Java --out appsec-reports/benchmarks/workflow-env-juliet
node bin/kayfabe.js benchmark sard appsec-out/benchmarks/sard-115 --out appsec-reports/benchmarks/workflow-env-sard
node bin/kayfabe.js benchmark cve-fixes appsec-out/cve-downloaded --out appsec-reports/benchmarks/workflow-env-cve
node scripts/score-supplied-apps.js appsec-out/supplied-benchmarks-2026-10-20/benchmarks/apps appsec-reports/benchmarks/workflow-env-after.json
node scripts/compare-workflow-env.js
```

The comparator uses the full `js-guards-config-*` reports and their committed
aggregates as the baseline. It checks source, dataset and scorer hashes, matching
policies, case identities and transitions, and rejects lost true positives or
new false positives. Only aggregate evidence is published; supplied source and
raw reports remain local.
