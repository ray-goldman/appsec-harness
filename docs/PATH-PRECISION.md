# Java normalized paths and Go local basenames

The supplied-app rerun reduces false-positive labels **12 → 11**, retaining
all **81 detected vulnerable labels**. The correction is Java's
`normalize-startswith` label at
`java-bank/src/main/java/bank/UtilController.java:30`.
The Go `filepath-base` label remains flagged. Inputs, labels and scorer are unchanged.

## Final measurements

| Dataset / policy | Cases | TP | FP before → after | TN after | FN |
|---|---:|---:|---:|---:|---:|
| OWASP Java 1.2 | 2,740 | 571 | 289 → 289 | 1,036 | 844 |
| Juliet Java 1.3 | 57,649 | 2,410 | 1,172 → 1,172 | 27,596 | 26,471 |
| SARD 115 | 20 | 10 | 0 → 0 | 0 | 10 |
| CVE historical file+CWE | 16 | 1 | 1 → 1 | 7 | 7 |
| Supplied application labels | 227 | 81 | 12 → 11 | 79 | 56 |

Every external case outcome is unchanged. Supplied cases have one `fp->tn`
transition, no lost true positives and no new false positives. Supplied FPR falls
from **13.33% to 12.22%** and precision rises from **87.10% to 88.04%**;
recall remains **59.12%**. These labels are unadjudicated, not independent
production accuracy evidence. The 54 manifest labels remain unscored and
unmatched findings remain unclassified.

Historical CVE scoring remains **0/8 complete pairs**. The separate localized
policy remains **1/8**, with TP=1, FP=0, TN=8, FN=7. SARD has no safe labels,
so its FPR is undefined.

Evidence: [case comparison](benchmarks/path-proofs-comparison.json),
[OWASP](benchmarks/owasp-java-1.2-path-proofs.json),
[Juliet](benchmarks/juliet-java-1.3-path-proofs.json),
[SARD](benchmarks/sard-115-path-proofs.json),
[CVE](benchmarks/cve-fixes-path-proofs.json), and
[supplied apps](benchmarks/supplied-apps-path-proofs.json).

All final runs used source SHA-256
`8e0ed5a3f529de65b9490d36420c38b717f8bf968fbd2465daee02f1d9414e70`,
on October 20, 2026, with Node v24.16.0 on Windows. Recorded timings are not
a controlled performance comparison.

## Java: prove the checked value reaches the read

The new proof recognizes one bounded method body:

1. Resolve a string parameter against a private, static, final root made with
   standard `Paths.get` and an absolute literal, followed by `toAbsolutePath`.
2. Normalize the resulting local `Path`.
3. Throw when that same path does not start with that same root.
4. Return `Files.readAllBytes` of that path, with no intervening statements.

Both the construction and read findings are removed. The first was outside the
supplied label's scoring window, so this is **one corrected label, two fewer
raw findings**. The guard is a `Path.startsWith` check, not a string-prefix test.

The proof checks library/type ownership and rejects static imports, shadowed
`Paths`/`Files`, conflicting source classes, nonstandard `String` imports,
inheritance, reflection indicators, incomplete project inventories and unsupported
syntax. It accepts only ordinary access-modified `byte[]` methods with one string
parameter, optional `@RequestParam`, and `throws IOException`. Method and field
formatting outside the recognized grammar retains the warning.

This is **lexical containment**, not a guarantee about symlinks, filesystem races,
authorization or deployment configuration. Java documents that normalization
does not access the filesystem and may change meaning when symbolic links are
involved. See [Path.normalize](https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/nio/file/Path.html#normalize())
and [Path.startsWith](https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/nio/file/Path.html#startsWith(java.nio.file.Path)).

## Go: why the supplied case remains

The supplied handler assigns `filepath.Base` to `name`, then reads
`filepath.Join(root, name)`. Another function also assigns request data to a
variable named `name`. Existing file-wide taint merges those bindings, while
the generic sanitizer heuristic recognizes `Base` on its assignment line.
That combination explains the warning; it is not a scoped analysis of the handler.

Removing the warning merely because the name came from `Base` would assume too
much. `Base` can return `..`; it is not a general lexical-containment check.
For this specific `ReadFile` use, reading a directory may instead fail, but the
scanner does not establish filesystem object types or symlink behavior. This
investigation does not claim the supplied handler is exploitable. Its safe
label remains unadjudicated, and its measured outcome remains FP.

The new Go proof supports the stronger form:

```go
name := filepath.Base(r.URL.Query().Get("name"))
if !filepath.IsLocal(name) { return }
data, _ := os.ReadFile(filepath.Join(root, name))
w.Write(data)
```

The root must be a top-level absolute literal constant. Standard-library imports
must own `filepath`, `os` and `http`; the complete handler body and parameter
bindings must match. Aliased library owners, mutable roots, extra statements,
reassignment, wrong guards and source-looking text inside strings retain warnings.
The supplied application has no `IsLocal` rejection and was not modified.
This new paired regression therefore adds supported coverage **without a measured
Go improvement**.

Go's [Base documentation](https://pkg.go.dev/path/filepath#Base) specifies its
special results. [IsLocal](https://pkg.go.dev/path/filepath#IsLocal), introduced
in Go 1.20, establishes a lexical condition under which joining to a base stays
inside it; it does not account for symbolic links.

## Bounds and remaining work

No target code is executed. A masked brace scan and complete-body patterns operate
on at most 100,000 characters, 64 brace levels and 4,000 characters per candidate
body. Java owner references are capped at 256 per name; import-prefix checks are
bounded. Unsupported Unicode/escape forms, parse shapes or ownership evidence
retain warnings. The proof applies only to `JAVA-PATH-001` and `GO-PATH-001`, and
only suppresses lines wholly contained in the proved body.

The [previous case review](WORKFLOW-ENV-PRECISION.md) records all 12 starting
labels. Java normalized-path containment is now resolved; the other 11 remain.
Next work should separate Go's function bindings and replace the generic basename
heuristic with sink-specific facts. Scope handling must preserve the distinction
between a basename, a local path and a filesystem-confined read. The URL, shell
platform and unresolved config cases retain their previously documented gaps.

## Review and verification

Both positive proof tests failed before implementation. Regression tests cover
wrong/incomplete guards, mutations, alternate sinks, roots and owners, custom
`String` bindings, static imports, generic fields and raw strings containing
source-looking text. The Go regression includes an unrelated same-named request
variable, reproducing the file-wide taint collision.

The first independent review found that static imports and generic fields could
shadow `Paths`. Scanner regressions reproduced both false suppressions before
the fixes. Static imports now reject the proof, and owner occurrences must be
supported static member reads or explicit standard-library imports. The reviewer
independently confirmed closure. The second independent review found no further
actionable issue.

All **190 tests** and **157 paired corpus cases** pass. All external benchmarks,
the supplied scorer and the case-by-case comparator passed against the reviewed
source. The documentation review also found no discrepancies.

## Reproduction

```text
npm test
npm run selftest
node bin/kayfabe.js benchmark owasp-java appsec-out/benchmarks/owasp-java --out appsec-reports/benchmarks/path-proofs-owasp
node bin/kayfabe.js benchmark juliet-java appsec-out/benchmarks/juliet-java-1.3/Java --out appsec-reports/benchmarks/path-proofs-juliet
node bin/kayfabe.js benchmark sard appsec-out/benchmarks/sard-115 --out appsec-reports/benchmarks/path-proofs-sard
node bin/kayfabe.js benchmark cve-fixes appsec-out/cve-downloaded --out appsec-reports/benchmarks/path-proofs-cve
node scripts/score-supplied-apps.js appsec-out/supplied-benchmarks-2026-10-20/benchmarks/apps appsec-reports/benchmarks/path-proofs-after.json
node scripts/compare-path-proofs.js
```

The comparator uses the full `workflow-env-*` reports and their committed
aggregates as the baseline. It checks source, input and scorer hashes, matching
policies, case identities and transitions, and rejects lost true positives or
new false positives. Supplied source and full raw reports remain local.
