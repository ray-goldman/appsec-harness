# Java helper calls and HTML encoding

This pass extends the existing Java constant proof through bounded helper calls
and tracks HTML text encoding across aliases and helper returns. Unknown calls,
ambiguous receivers and unsupported output contexts retain warnings.

## Measurement

Compared with the previous [scope and branch measurements](JAVA-SCOPE-BRANCHES.md):

| Dataset / policy | TP before → after | FP before → after | FPR before → after | Precision before → after |
|---|---:|---:|---:|---:|
| Juliet Java 1.3, 57,649 units | 2,410 → 2,410 | 1,226 → 1,172 | 4.26% → 4.07% | 66.28% → 67.28% |
| OWASP Java 1.2, 2,740 cases | 571 → 571 | 301 → 291 | 22.72% → 21.96% | 65.48% → 66.24% |
| SARD 115, 20 vulnerable locations | 10 → 10 | 0 → 0 | undefined → undefined | 100% → 100%* |
| CVE historical file+CWE, 16 snapshots | 1 → 1 | 1 → 1 | 12.50% → 12.50% | 50% → 50% |

Juliet has **54 fewer false positives (4.40%)**, all from previously flagged
negative units. OWASP has **11 corrected FPs and one new FP**, a net reduction
of **10 (3.32%)**. Across the two Java suites, that is 64 fewer FPs overall.
Case-by-case comparison found **zero lost previously detected true positives**
across all four datasets. The new OWASP warning is explained below.

| Changed category | FP before → after |
|---|---:|
| Juliet SQL injection, CWE-89 | 956 → 920 |
| Juliet command injection, CWE-78 | 228 → 210 |
| OWASP command injection, CWE-78 | 72 → 70 |
| OWASP XSS, CWE-79 | 105 → 97 |

Recall remains 8.34% for Juliet, 40.35% for OWASP and 50% for SARD.
Historical CVE scoring remains **0/8 complete pairs**. The separate localized
policy remains **1/8**, with TP=1, FP=0, TN=8 and FN=7. These are unchanged
policies, not interchangeable measures.

*SARD has no safe labels, so its apparent precision cannot support a
false-positive claim.*

The [comparison JSON](benchmarks/java-helper-sanitizer-comparison.json) records
all transitions, corrected case IDs, the new FP ID, per-CWE counts and input
hashes. New aggregates: [Juliet](benchmarks/juliet-java-1.3-helper-sanitizer.json),
[OWASP](benchmarks/owasp-java-1.2-helper-sanitizer.json),
[SARD](benchmarks/sard-115-helper-sanitizer.json) and
[CVE](benchmarks/cve-fixes-helper-sanitizer.json). Earlier reports are preserved.

All four runs used unchanged inputs, labels and scoring policies, with source
SHA-256 `ca20b08f296449f8a58e99b24768975c497ca8babcbd2b3a177368e3e8afc671`.
Measured October 20, 2026, using Node v24.16.0 on Windows. Juliet's recorded
scanner phase took **184.8 seconds**, versus 127.9 before; OWASP took **14.7
seconds**, versus 9.8 before. These were concurrent, uncontrolled measurements,
excluding preparation and reporting. The extra source indexing and proof work
have a measurable cost; profiling is part of the next pass.

Reproduce using the previously downloaded, unchanged inputs:

```sh
node bin/appsec.js benchmark owasp-java appsec-out/benchmarks/owasp-java --out appsec-reports/benchmarks/helper-sanitizer-owasp
node bin/appsec.js benchmark juliet-java appsec-out/benchmarks/juliet-java-1.3/Java --out appsec-reports/benchmarks/helper-sanitizer-juliet
node bin/appsec.js benchmark sard appsec-out/benchmarks/sard-115 --out appsec-reports/benchmarks/helper-sanitizer-sard
node bin/appsec.js benchmark cve-fixes appsec-out/cve-downloaded --out appsec-reports/benchmarks/helper-sanitizer-cve
```

### Newly exposed warning

OWASP `BenchmarkTest00718` is a new false positive under the unchanged label:
it passes an `Object[]` containing a literal and an HTML-escaped value to
`printf`. This concrete array is safe. The former generic sanitizer shortcut
removed taint before the sink; the new proof does not yet establish array
contents, mutation and escape behavior. The warning remains, is counted as an
FP, and is included in the transition report. The label is not disputed.
Supporting this pattern needs an array proof, rather than restoring the old
name-based exclusion.

## What the proof supports

A helper return can qualify when every return expression is independent of
external input, or every return carries the required HTML text guarantee.
Arguments are specialized per call; a safe invocation does not make another
invocation safe. Private sink parameters require all visible callers to pass
the proof. Reflection, incomplete source coverage and unsupported references
disable that caller-closure inference.

Static calls across files require an unambiguous source class and method.
Supported argument types must match exactly; unknown types and widening
conversions cannot borrow a summary from a competing inherited overload.
Overloads, virtual calls, unknown superclass fields, interface fields, duplicate
classes and value receivers that shadow a class name remain unknown.
Superclass lookup is bounded. No target code is compiled or executed.

HTML models cover exact Spring `HtmlUtils.htmlEscape`, OWASP Java Encoder
`forHtml`/`forHtmlContent`, and Commons HTML-escape methods. Qualified names and
explicit imports must resolve without source or value shadowing. The encoded
value still carries external input provenance: HTML encoding cannot make a
SQL expression, command or redirect safe.

At a supported servlet writer, the proof reconstructs preceding output and
checks every dynamic piece in HTML document text. Integer `write` arguments
emit characters; `println` contributes a newline. Literal fragments and
simple tags without attributes, plus supported scalar `printf` substitutions,
preserve their structure. A direct
`String.toCharArray()` copy can qualify; a stored mutable array cannot.

An alias or helper summary containing structural markup cannot become a generic
HTML text fact. Script/style bodies, attributes, unknown writers, conditional
output, loops and unmodeled response operations retain warnings. ESAPI's
configurable provider is not inferred from its method name.
Comments and raw-text tags remain unknown even when a closing marker appears:
the model does not implement browsers' comment and script escaped states.

The existing `a05-java-injection-pack` safe response helper now explicitly resets
the buffer and selects HTML before writing. Its old form lacked a known caller
output context; that ambiguous form remains a warning regression. External
benchmark sources and labels were not edited.

## Resource limits

The source index retains at most 50,000 files and 100 MiB. Each supported file
has one top-level class, at most 256 methods, 16 parameters per method and
32 return expressions per method. Helper proofs stop at depth four, 32 methods,
64 private call references and 10,000 shared work steps. Existing local-expression,
scope and statement limits still apply.

Output reconstruction accepts at most 64 prior writer calls and 16,000
characters. Missing files, skipped Java sources, Unicode preprocessing,
unsupported syntax and exhausted budgets retain findings. This is a bounded
source proof, not a complete Java parser or call graph.

## Review record

The first independent review reproduced and verified fixes for:

- Reflective calls that bypass private caller enumeration.
- Superclass and interface fields mistaken for imported class owners.
- Conditional and repeated output that changes the HTML parsing context.
- A safe writer suppressing a different unsafe writer on the same line.
- Script markup hidden inside encoded aliases and helper summaries.
- Integer writer overloads and `println` newlines.
- HTML encoding incorrectly clearing taint for other injection contexts.

The second independent review found inherited overloads selected without
argument types, comma-declared fields mistaken for class owners, unsupported
HTML parser states treated as text, and skipped source directories treated as
complete coverage. Each has a regression test. Skipped source-bearing
directories now prevent ownership and caller-closure proofs; ordinary VCS
metadata directories are exempt.

Both reviewers independently verified the fixes with scan-only adversarial
probes: 13 in the first pass and nine in the second. The final focused suite
passed 37 tests. On the frozen implementation, `npm test` passed 150 tests and
`node bin/appsec.js selftest` passed all 149 vulnerable/fixed pairs.
One Windows symlink subcheck could not create a link; its separate source
tampering check passed. The regression corpus was developed alongside the
rules and does not measure independent accuracy.

## Next false-positive work

1. Resolve the remaining helper and receiver shapes from measured case IDs.
   Juliet variants 41/42 still contain 83 FP units: 64 SQL, 15 command and four
   redirect. These are candidate counts, not promised recoveries. This pass
   corrected 45 variant-42 units and nine variant-21 units. Corpus-wide
   completeness/reflection fallbacks can disable private caller closure;
   improve the identity index and scoped resolution without assuming away
   unknown callers. Public and virtual dispatch need explicit modeling.
2. Model immutable formatting arrays with mutation and escape checks. Do not
   infer safety from the presence of an encoder in one array element.
3. Connect HTML encoding to supported writer aliases and method contexts.
   Inner classes and configurable ESAPI providers need separate models.
4. Recognize SQL receivers through JDBC types. In particular, a receiver named
   `sqlStatement` should not depend on a name-based sink regex.
5. Add held-out projects and SARD datasets with safe labels before claiming
   production precision. These benchmark suites are now development data.
6. Profile and reuse parsed source structures, preserving the same case
   transitions and conservative fallback behavior while reducing scan cost.

Collections, object fields, general cross-file taint, reflection, virtual
dispatch and complete output control flow remain outside this pass.
The scanner also retains older numeric and non-HTML validator-name heuristics;
this change does not establish their general soundness. Juliet's existing
cryptographic label disagreements remain visible.
