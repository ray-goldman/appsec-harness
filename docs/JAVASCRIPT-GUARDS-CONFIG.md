# JavaScript hostname guards and config exports

This pass adds bounded command-injection proofs for primitive-string hostname
helpers and literal config exports. It follows the [computed-read work](JAVASCRIPT-OWNERSHIP.md).
The supplied applications and their labels are unchanged.

## Final measurements

| Dataset / policy | Cases | TP | FP before → after | TN | FN |
|---|---:|---:|---:|---:|---:|
| OWASP Java 1.2 | 2,740 | 571 | 289 → 289 | 1,036 | 844 |
| Juliet Java 1.3 | 57,649 | 2,410 | 1,172 → 1,172 | 27,596 | 26,471 |
| SARD 115 | 20 | 10 | 0 → 0 | 0 | 10 |
| CVE historical file+CWE | 16 | 1 | 1 → 1 | 7 | 7 |
| Supplied application labels | 227 | 81 | 13 → 13 | 77 | 56 |

Every case outcome is unchanged across all five suites: **no measured FP
reduction, no lost true positives and no new false positives**. The two new
paired cases demonstrate narrower regression coverage, not held-out accuracy.
Supplied FPR remains 14.44%, precision 86.17% and recall 59.12%; 54 manifest
labels remain unscored, and unmatched findings remain unclassified.

Historical CVE scoring remains **0/8 complete pairs**. The separate localized
policy remains **1/8**, with TP=1, FP=0, TN=8, FN=7. SARD has no safe labels,
so its FPR is undefined.

Evidence:
[case comparison](benchmarks/js-guards-config-comparison.json),
[OWASP](benchmarks/owasp-java-1.2-js-guards-config.json),
[Juliet](benchmarks/juliet-java-1.3-js-guards-config.json),
[SARD](benchmarks/sard-115-js-guards-config.json),
[CVE](benchmarks/cve-fixes-js-guards-config.json), and
[supplied apps](benchmarks/supplied-apps-js-guards-config.json).

All final runs used source SHA-256
`a367750e1b78c255fe08ce7b9457c3073ac96fba0e834ccdc3e841f1ad14c9e5`,
on October 20, 2026, with Node v24.16.0 on Windows. Scan timings are recorded
in the comparison artifact. Concurrent runs, filesystem variation and excluded
preparation/report-writing time prevent interpreting them as a performance
benchmark.

## Label review and scope

The supplied hostname helper checks `String(h)` and then concatenates the
original value. It has no primitive-string check. The config route imports an
unresolved `./db` dependency, and its config object is mutable. These gaps remain;
this change does not suppress those labels or claim a measured improvement on
the supplied apps. The shell-quoting case still needs an explicit platform.

New paired regression cases establish two narrower supported forms:

- A helper checks `typeof host === 'string'`, length 1–253, and rejects every
  character outside ASCII letters, digits, dot and hyphen. The caller stores a
  request property in a local `const`, immediately returns when the helper
  rejects it, and then passes `ping -c1 ` or `nslookup ` plus that same variable
  to `exec`.
- A local config module exports one literal object containing only string
  fields. A caller concatenates those fields and string literals. All admitted
  JavaScript imports resolve to explicit local `.js` files or the modeled
  `child_process.exec` API. Namespace aliases, mutation, shadowing, dynamic
  values and unresolved imports retain the warning.

The hostname proof prevents shell-operator injection (CWE-78). It does not
establish valid DNS syntax, command authorization, or protection against
leading-option injection (CWE-88). The invalid-character regex rejects newline
characters too; it does not rely on JavaScript's permissive final `$` anchor.

## Implementation limits

The optional vendored parser reads source as data. The existing capability
proof must succeed before either new proof is used. Its file/size/node/depth
and fixed-point limits still apply. A second bounded AST walk verifies imports,
helper bodies, statement order and config values. Parse failures and unsupported
syntax retain warnings. No target code is executed.

Only `JS-CMDI-001`, direct imported `exec` calls, and top-level ordinary function
declarations are supported. Calls must occupy their own line and have one
argument. Callback/options arguments, arrow-route handlers, escaped export
objects, computed config lookups, extensionless imports, helper wrappers and
other control-flow shapes are outside this proof. The hostname caller has
exactly three statements; the config caller has one command statement.
Assignments other than explicit `module.exports = …` statements reject the
command proof for the entire admitted project. The shared capability proof
also rejects object/array destructuring assignment targets.

These restrictions are deliberate: additional source/context support needs its
own ownership and effect checks. Ordinary Node built-ins and the admitted
source set are assumed; this is not a guarantee against changes introduced by
unscanned runtime code.

## Verification record

Both positive tests failed before implementation. The focused suite now also
checks coercing/permissive/stateful validators, missing early returns, intervening
statements, extra request concatenation, mutable exports, unresolved imports,
dynamic config values and shadowed namespace bindings. Two new paired corpus
cases retain vulnerable controls.

The first independent static review found that a generic prefix could name an
interpreter rather than a hostname-consuming command. The proof now accepts
only `ping -c1 ` and `nslookup `; interpreter-context regression tests failed
before the fix and passed afterward. The reviewer independently confirmed
closure.

The second independent static review found a config mutation path through
destructuring assignment targets. New negative object/array-write tests and a
direct parser assertion exposed the gap. Both the command proof and shared
capability gate now reject the unsupported writes. Both reviewers independently
rechecked this fix and reported no remaining actionable findings. Reviews used
static inspection; test snippets were scanned as data, never executed.

Final local verification: **183 tests pass; all 154 paired corpus cases pass**.
All four external benchmarks and the supplied scorer were rerun after the
last source change. The comparison script passed every invariant.

## Reproduction

Using the pinned datasets from the preceding benchmark reports:

```text
node bin/kayfabe.js benchmark owasp-java appsec-out/benchmarks/owasp-java --out appsec-reports/benchmarks/js-guards-config-owasp
node bin/kayfabe.js benchmark juliet-java appsec-out/benchmarks/juliet-java-1.3/Java --out appsec-reports/benchmarks/js-guards-config-juliet
node bin/kayfabe.js benchmark sard appsec-out/benchmarks/sard-115 --out appsec-reports/benchmarks/js-guards-config-sard
node bin/kayfabe.js benchmark cve-fixes appsec-out/cve-downloaded --out appsec-reports/benchmarks/js-guards-config-cve
node scripts/score-supplied-apps.js appsec-out/supplied-benchmarks-2026-10-20/benchmarks/apps appsec-reports/benchmarks/js-guards-config-after.json
node scripts/compare-js-guards-config.js
```

Comparison uses the previous full `javascript-ownership-*` reports and a fresh
supplied baseline at commit `348dd7d4c7e879dcff2a70d32f7eca18e51397a0`.
Its source SHA-256 is
`77d7d13757ca47958a33123ea69de72c5d9739aed86fe4ee571824f6fe3a133e`;
checkout line endings differ from the previous published run. Input bytes,
scorer bytes, labels and baseline outcomes are asserted unchanged. Final
reports must match the current source hash, preserve case identities and
contain no lost true positives or newly introduced false positives.
