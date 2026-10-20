# Java formatting arrays

This pass addresses OWASP `BenchmarkTest00718`, the safe formatting-array case
newly exposed by the helper and HTML-encoding work. The implementation adds a
bounded ownership proof for local arrays. It does not change external labels,
scoring policies or sanitizer names.

## Results

| Dataset / policy | TP | FP before → after | TN | FN | FPR | Precision |
|---|---:|---:|---:|---:|---:|---:|
| OWASP Java 1.2, 2,740 cases | 571 | 291 → **289** | 1,036 | 844 | 21.81% | 66.40% |
| Juliet Java 1.3, 57,649 units | 2,410 | 1,172 → 1,172 | 27,596 | 26,471 | 4.07% | 67.28% |
| SARD 115, 20 vulnerable locations | 10 | 0 → 0 | 0 | 10 | undefined | 100%* |
| CVE historical file+CWE, 16 snapshots | 1 | 1 → 1 | 7 | 7 | 12.50% | 50% |

OWASP corrections are `BenchmarkTest00471` and `BenchmarkTest00718`, both XSS
cases with an HTML-encoded value in a formatting array. OWASP XSS FPs drop
from 97 to 95; total FPs drop by **0.69%**. Case-by-case comparison across all
four datasets found **zero lost previously detected true positives and zero
new false positives**. All other case outcomes are unchanged.

Recall remains 40.35% on OWASP, 8.34% on Juliet and 50% on SARD.
Historical CVE scoring remains **0/8 complete pairs**. The separate localized
policy remains **1/8**, with TP=1, FP=0, TN=8 and FN=7. This small precision
improvement does not address the missed CVE mechanisms.

*SARD has no safe labels; its apparent precision does not establish
false-positive performance.*

The [comparison JSON](benchmarks/java-format-arrays-comparison.json) records
transitions, case IDs, per-CWE results, policies and input hashes. Aggregates:
[OWASP](benchmarks/owasp-java-1.2-format-arrays.json),
[Juliet](benchmarks/juliet-java-1.3-format-arrays.json),
[SARD](benchmarks/sard-115-format-arrays.json), and
[CVE](benchmarks/cve-fixes-format-arrays.json).

All four final runs used source SHA-256
`711952d09f48011bfaf229602078533f27017a3a30bcd73f98bd1a64e93a9944`,
on October 20, 2026, with Node v24.16.0 on Windows. The recorded scan phases
took 13.7 seconds for OWASP and 190.4 seconds for Juliet, compared with
14.7 and 184.8 seconds previously. These concurrent, uncontrolled timings
exclude preparation and report writing and do not establish a speed change.
Runs from before the second review's fix were superseded; the final reports
all match the fixed scanner's hash.

## Supported proof

The carrier must be a top-level local `Object[]` or `String[]` with a literal
initializer, optionally `final`. The array name must appear exactly twice in
the method: once in its declaration and once as the entire varargs carrier of
the current `response.getWriter().printf` call.

```java
String clean = org.springframework.web.util.HtmlUtils.htmlEscape(input);
Object[] parts = {"label", clean};
response.getWriter().printf("<p>%1$s: %2$s</p>", parts);
```

Every initializer must be a literal scalar or a simple local scalar read.
Calls, constructors, assignments and other expressions remain unsupported,
including in unused elements: Java evaluates them before the writer call,
and their side effects could change the output context.

The proof resolves selected elements at their initializer, renders them in
placeholder order, and retains literal markup. Each selected dynamic value
must have an HTML-text encoding guarantee at a known HTML-text output position.
A literal, an encoded value and an unencoded value in one array are not treated
as sharing one sanitizer.

Any additional array reference makes the proof unknown. This includes
reassignment, element writes, aliases, field storage, calls, and references
after the sink. Nested declarations and loops also remain unknown. Unused
scalar values are not rendered: a raw scalar read that no placeholder selects
does not itself reach the writer. Unknown object conversions cannot be proved safe.

The limits are a 50,000-character method, a 4,000-character initializer and
32 elements. Existing output limits still apply: 64 preceding response writes
and 16,000 reconstructed characters. Explicit `new Object[]` expressions,
multiple array uses, fields, array parameters, casts, writer aliases and
unsupported formatting conversions retain warnings.

This is a small conservative proof, not an immutability type system or Java
parser. The initializer-only syntax avoids broadening the existing guard
against anonymous classes. The code does not special-case benchmark names.

## Evaluation protocol

The comparison uses the prior `helper-sanitizer` reports as its baseline. All
four datasets retain their prior input bytes, expected labels and policies.
The comparison checks scanner hashes, case IDs and transitions, including
previously detected true positives. Original reports remain unchanged.

```sh
node bin/kayfabe.js benchmark owasp-java appsec-out/benchmarks/owasp-java --out appsec-reports/benchmarks/format-arrays-owasp
node bin/kayfabe.js benchmark juliet-java appsec-out/benchmarks/juliet-java-1.3/Java --out appsec-reports/benchmarks/format-arrays-juliet
node bin/kayfabe.js benchmark sard appsec-out/benchmarks/sard-115 --out appsec-reports/benchmarks/format-arrays-sard
node bin/kayfabe.js benchmark cve-fixes appsec-out/cve-downloaded --out appsec-reports/benchmarks/format-arrays-cve
node scripts/compare-format-arrays.js
```

The [supplied applications](SUPPLIED-APPS.md) have a separate, provisional
line-label baseline. Their source and labels do not alter these four scores.

## Review record

The first fresh-context reviewer found no blocking issues and ran 12 scan-only
adversarial probes, covering mutations, aliases, callback arguments and HTML
context ordering.

The second reviewer found an unsafe suppression: an unused initializer could
call `request.startAsync().getResponse().getWriter().append("<script>")`.
Java evaluates that call before `printf`, even if the format selects only a
different, encoded element. A return-value encoding fact does not establish
that a call is free of side effects.

The fix checks every initializer and rejects calls and other unsupported
expressions. A regression test failed before the fix and passed afterward.
The reviewer independently verified the original reproducer and ten related
forms; they now retain warnings. Literal scalars and unused raw local reads
still work. The review also strengthened the report comparator to check the
local baseline's input hashes and policy against the committed baseline.
Both reviews ended without outstanding Critical or Important findings.

Final verification: **158 tests passed**, including 27 focused sanitizer/scorer
tests, and **all 150 vulnerable/fixed corpus pairs passed**. These regression
tests were developed with the implementation and do not establish independent
accuracy.

## Remaining work

1. Java helper receivers, public/virtual dispatch, writer aliases and method
   contexts still limit the existing proofs. Start from remaining measured case
   IDs, and preserve unsafe neighboring cases when expanding coverage.
2. Repeated array uses and explicit `new Object[]` forms require separate
   ownership and parsing work. Do not replace the reference-count check with a
   name-based sanitizer shortcut.
3. Side effects outside array initializers are not comprehensively modeled.
   Broader helper summaries need both return-value and effect information before
   they can establish a writer's complete output context.
4. Taint discovery remains line-oriented; multiple declarations on one line can
   be missed before the output proof runs. Conservative proof failure cannot
   recover a finding that the initial scanner did not emit.
5. The [supplied apps](SUPPLIED-APPS.md) identify helper-flow and guard candidates
   in JavaScript, Python, Go and Java, but their labels need adjudication.
   Package labels need an identity-aware scoring adapter.
6. Independent held-out projects, safe SARD examples and mechanism-specific
   detection for the missed CVE parents remain necessary. None of the scores
   measures triage-agent accuracy or production precision.
