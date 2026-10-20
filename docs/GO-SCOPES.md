# Go local bindings and the unchanged basename warning

**The supplied false-positive count remains 11.** All 81 detected vulnerable
labels remain detected. The new paired regression fixes a literal-local name
collision, but none of the 11 remaining supplied labels has that supported shape.
Inputs, labels and scoring policy are unchanged.

## What changed

Go now computes taint within supported function bodies and retains file-wide
evidence for unknown bindings. A literal local string can be isolated from an
unrelated same-named variable only when its declaration and uses establish that
it stays unchanged in a straight-line body. This removes the regression where
one function reads request data into `name` and another independently reads a
literal `name` such as `README.txt`.

This is bounded scope support, not a full Go resolver or call graph. It does not
remove file-wide evidence for arbitrary locals, parameters, package globals,
unknown helper results or unsupported syntax. Receivers, multiline signatures,
closures, `goto`, `go` and `defer` use the prior analysis. Control statements and
address-taking prevent literal isolation. Complex aliases and assignments retain
warnings. Source references in diagnostics are mapped back to file lines.

For `GO-PATH-001`, the function-local pass does not treat generic sanitizer names
as safety evidence. Other Go rules retain their previous sanitizer policy. The
existing path proof still recognizes `Base` followed by a rejecting `IsLocal`
guard. Existing rule-level exclusions are unchanged; this pass is not a complete
replacement of all sanitizer heuristics.

## Investigation: why 11 did not decrease

The remaining Go basename label is `go-api/main.go:71`. The
[static diagnostic](benchmarks/go-basename-diagnostic.json) records these results
from the unchanged supplied file:

| Analysis | Is `name` tainted at the read? | Evidence |
|---|---|---|
| Previous file-wide heuristic | Yes | Assignment at line 62, in another function |
| Function-only analysis with generic sanitizers | No | The generic `filepath.Base` sanitizer heuristic drops taint |
| Function-only analysis without generic sanitizers | Yes | The handler's own basename assignment |
| Current path analysis | Yes | File line 69, the handler's own request-derived assignment |

Function isolation alone would therefore improve the count by relying on the
generic basename heuristic. It would not establish that the file read is confined.
The new analysis keeps the warning and corrects its taint origin. The diagnostic
does not execute the target, mutate its source or alter its labels.

`filepath.Base` can return `..`; it is not a general containment check. The exact
`ReadFile` outcome also depends on filesystem types and links. A directory read
may fail, but this source does not establish the deployment's filesystem state.
This is **not a claim that the supplied handler is exploitable**. Its `safe` label
remains unadjudicated, and the scorer continues to count the warning as an FP.
See [Go's Base documentation](https://pkg.go.dev/path/filepath#Base) and
[IsLocal's lexical guarantees](https://pkg.go.dev/path/filepath#IsLocal).

Three remaining labels are in the Go app: basename, command arguments and the
HTTP host guard. All are request-derived, not immutable literal-local bindings.
The other eight labels are outside Go and are unaffected by this change. Their
gaps remain recorded in the [workflow case review](WORKFLOW-ENV-PRECISION.md),
with Java's normalized-path correction covered by the [path pass](PATH-PRECISION.md).

The next useful work is explicit label adjudication and sink-specific models:

- Establish the basename case's filesystem assumptions before calling it safe,
  or assess a separate strengthened example with a local-path rejection. Do not
  replace the original input and present that as detector improvement.
- Separate Go command injection from argument injection, keeping taxonomy changes
  distinct from safety proofs.
- Model redirect behavior before suppressing initial-host SSRF guards.
- Extend local-binding support with a real Go parser or an explicit supported
  grammar before admitting branches, captures and helper effects.

## Bounds and review findings

The scope pass handles at most 100,000 source characters, 64 brace levels, 256
functions, 16,000 characters per function, 64 eligible locals and 256 uses per
local. Parenthesis inspection is capped at 256 characters. Unsupported non-ASCII,
NUL, unsafe/cgo/linkname indicators, and combined raw-string/backslash forms use
the prior file-wide analysis. These fallbacks do not claim safety.

The first independent review found parenthesized address escapes and assignments
that could mutate a supposedly safe local. Its recheck found a spaced nested-
parenthesis variant. Scanner regressions reproduced the failures; address-taking
now prevents isolation and a bounded character scan checks closing parentheses
and whitespace before stores.

The second independent review found declarations in multiline `if` headers were
misclassified as function locals. Tests now cover `if`, `for` and `switch`
headers. Such control-flow bodies retain file-wide evidence. Both reviewers
independently rechecked the fixes and reported no remaining actionable findings.

An intermediate full-suite run also found that disabling generic sanitizers for
all Go rules changed an existing command fixture. The stricter policy was limited
to path findings, and the entire suite was rerun successfully. No target code,
workflows, dependency installers or target tests were executed.

## Final measurements

All case outcomes are unchanged from PR #12, including the 11 supplied false
positives. The comparator found no lost true positives or new false positives.

| Dataset | Cases | TP | FP before → after | TN | FN |
|---|---:|---:|---:|---:|---:|
| [OWASP Java 1.2](benchmarks/owasp-java-1.2-go-scopes.json) | 2,740 | 571 | 289 → 289 | 1,036 | 844 |
| [Juliet Java 1.3](benchmarks/juliet-java-1.3-go-scopes.json) | 57,649 | 2,410 | 1,172 → 1,172 | 27,596 | 26,471 |
| [SARD 115](benchmarks/sard-115-go-scopes.json) | 20 | 10 | 0 → 0 | 0 | 10 |
| [CVE historical policy](benchmarks/cve-fixes-go-scopes.json) | 16 | 1 | 1 → 1 | 7 | 7 |
| [Supplied apps](benchmarks/supplied-apps-go-scopes.json) | 227 | 81 | 11 → 11 | 79 | 56 |

The CVE localized policy also remains unchanged: 1 TP, 0 FP, 8 TN and 7 FN,
with 1/8 successful parent/fix pairs. The historical policy remains at 0/8 pairs.
SARD has no negative labels, so its false-positive rate is undefined. The
supplied scorer still leaves 54 manifest labels unscored and unmatched findings
unclassified; these totals do not describe all vulnerabilities in those apps.

All **193 tests** and **158 paired regression cases** pass on the final source.
The [comparison record](benchmarks/go-scopes-comparison.json) records the external
case transitions; the supplied aggregate includes its own transitions. All runs
and the basename diagnostic use source SHA-256
`7db335b475b01da832a96429ffd2a80b8184268465188e4d13e62c8d7ee4b401`.

## Reproduction

```text
npm test
npm run selftest
node bin/kayfabe.js benchmark owasp-java appsec-out/benchmarks/owasp-java --out appsec-reports/benchmarks/go-scopes-owasp
node bin/kayfabe.js benchmark juliet-java appsec-out/benchmarks/juliet-java-1.3/Java --out appsec-reports/benchmarks/go-scopes-juliet
node bin/kayfabe.js benchmark sard appsec-out/benchmarks/sard-115 --out appsec-reports/benchmarks/go-scopes-sard
node bin/kayfabe.js benchmark cve-fixes appsec-out/cve-downloaded --out appsec-reports/benchmarks/go-scopes-cve
node scripts/score-supplied-apps.js appsec-out/supplied-benchmarks-2026-10-20/benchmarks/apps appsec-reports/benchmarks/go-scopes-after.json
node scripts/explain-go-basename.js appsec-out/supplied-benchmarks-2026-10-20/benchmarks/apps/go-api/main.go docs/benchmarks/go-basename-diagnostic.json
node scripts/compare-go-scopes.js
```

The comparator uses the full `path-proofs-*` reports and their committed
aggregates as the baseline. Source/input/scorer hashes, policies and case
transitions are checked, including lost true positives and new false positives.
The diagnostic reports its own supplied-file hash; body-only diagnostic line
numbers are relative to that extracted body. Full raw reports and supplied source
remain local.
