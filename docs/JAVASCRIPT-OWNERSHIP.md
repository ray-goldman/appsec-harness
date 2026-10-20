# JavaScript computed reads and numeric SQL

This pass revisits the supplied JavaScript helper cases after the
[safe-label review](SUPPLIED-HELPER-LABEL-REVIEW.md). The numeric SQL case at
`xfile-lab/js/routes.js:74:numeric-cast-then-concat` converts helper output
with `Number` before concatenation into an unquoted numeric position.
Previously, unrelated computed reads anywhere in the project disabled that
proof. The final run removes this one labeled false positive.

## Final measurements

| Dataset / policy | Cases | TP | FP before → after | TN | FN |
|---|---:|---:|---:|---:|---:|
| OWASP Java 1.2 | 2,740 | 571 | 289 → 289 | 1,036 | 844 |
| Juliet Java 1.3 | 57,649 | 2,410 | 1,172 → 1,172 | 27,596 | 26,471 |
| SARD 115 | 20 | 10 | 0 → 0 | 0 | 10 |
| CVE historical file+CWE | 16 | 1 | 1 → 1 | 7 | 7 |
| Supplied application labels | 227 | 81 | **14 → 13** | 77 | 56 |

Case-by-case comparison found exactly one FP→TN transition, the numeric SQL
label above, and no other changes across all five suites. There are zero
lost previously detected true positives and zero new false positives.
Supplied-label FPR falls **15.56% → 14.44%** and precision rises
**85.26% → 86.17%**; recall remains **59.12%**. The 54 manifest labels remain
unscored, and unmatched findings are not automatically false positives.

Historical CVE scoring remains **0/8 complete pairs**. The separately
versioned localized policy remains **1/8**, with TP=1, FP=0, TN=8, FN=7.
SARD has no negative labels, so its FPR is undefined.

Evidence:
[case comparison](benchmarks/javascript-ownership-comparison.json),
[OWASP](benchmarks/owasp-java-1.2-javascript-ownership.json),
[Juliet](benchmarks/juliet-java-1.3-javascript-ownership.json),
[SARD](benchmarks/sard-115-javascript-ownership.json),
[CVE](benchmarks/cve-fixes-javascript-ownership.json), and
[supplied apps](benchmarks/supplied-apps-javascript-ownership.json).

All final runs used source SHA-256
`7a22ea15d9cebb471dd4a3d95296be327279e58d26d606b9bf34778a2686da7e`,
on October 20, 2026, with Node v24.16.0 on Windows. Recorded scan phases
were 16.4 seconds for OWASP and 185.5 seconds for Juliet, versus 15.4 and
189.9 previously. Concurrent runs and filesystem variation prevent treating
these timings as a performance comparison; preparation and report writing
are excluded.

## Bounded syntax proof

Computed reads can retrieve functions, including constructors that generate
code. The new optional parser follows those values through local bindings,
arguments and return values. It permits modeled data consumers and retains
warnings when a value might become executable JavaScript.

The implementation parses source without loading target modules. It has
limits of 200 JavaScript files, 250,000 characters, 50,000 AST nodes, depth 160
and 32 propagation passes. Unsupported syntax, exhausted limits, parse errors
or a missing parser retain the previous warning. Numeric SQL still requires
the existing adjacent conversion and built-in identity checks.

This is a narrow capability analysis, not general cross-file request taint.
It assumes ordinary behavior from the modeled APIs and external runtime
dependencies. It does not prove that installed dependencies are benign.
Dynamic loaders, code-generation APIs, unsupported calls, property mutation,
iteration/default bindings and constructors with explicit returns are rejected.
Local classes without inheritance are the only supported construction form.
Function aliases are restricted to explicit exports; capable exported returns
cannot be consumed through member dispatch. Anonymous function return
summaries propagate through containers and factories.
Loader aliases, sensitive destructuring keys and imported method extraction
are rejected. Namespace data reads require a resolved local literal-object
export; namespace method calls remain limited to the modeled API names.

### Parser distribution

Acorn 8.19.0 is vendored under `src/parsers`, with its MIT license, archive
integrity and individual file hashes. No `npm install` is needed. The parser
loads only for the computed-read proof; the regex scanner remains usable
without it. This is a limited implementation of the roadmap's optional
vendored parsing layer; it does not add tree-sitter or a general call graph.

To update it, verify the upstream archive against registry integrity,
extract only the parser distribution and license, record their SHA-256 hashes
in `acorn.provenance.json`, and rerun ownership tests, the corpus and all
benchmarks. `.gitattributes` preserves the pinned upstream bytes on Windows.

## Cases deliberately left open

- The shell-quoting label depends on a POSIX shell; the source does not
  establish that platform.
- The hostname helper checks `String(h)` while the sink consumes `h`.
  Repeated object coercion can produce a different value.
- Command constants are exported through mutable objects. The project also
  has an unresolved database import. These do not establish immutable
  ownership of the exported configuration.

The supplied labels and scorer remain unchanged. These small apps were
written alongside scanner rules and provide regression evidence. They are
not an independent production-accuracy estimate.

## Review and measurement record

The first independent reviewer found unsafe suppression through constructor
returns, iteration bindings, and discarded method return capabilities.
Follow-up probes covered ordinary aliases, exported aliases, anonymous
function factories, default parameters, prototype destructuring, loader
aliases and imported filesystem method aliases. Scanner-level reproducers
were observed failing before their fixes and retained as regressions. The fixes reject unsupported construction,
iteration and dispatch, and propagate anonymous function return summaries.
Target snippets were scanned as text and never executed.
An automated cybersecurity check blocked the first reviewer's final recheck.
Its earlier findings and the implemented fixes were handed to the second
independent reviewer for static verification; the blocked recheck is not
reported as a clean review.

The second independent review statically rechecked the earlier fixes and
found two more unsupported flows: implicit `arguments` and spread call
arguments. Both now retain warnings. Harmless syntax assertions failed before
the fixes and passed afterward. The reviewer independently confirmed both
closures and reported no remaining actionable findings. This second pass
used static inspection, without generating further adversarial snippets.

Final local verification: **179 tests pass; all 152 paired corpus cases pass**.
All four external benchmarks and the supplied scorer were rerun after the
last source change; the comparison script passed every invariant.

## Reproduction

Use the pinned local datasets prepared in the earlier benchmark reports.
These commands scan their source as data:

```text
node bin/kayfabe.js benchmark owasp-java appsec-out/benchmarks/owasp-java --out appsec-reports/benchmarks/javascript-ownership-owasp
node bin/kayfabe.js benchmark juliet-java appsec-out/benchmarks/juliet-java-1.3/Java --out appsec-reports/benchmarks/javascript-ownership-juliet
node bin/kayfabe.js benchmark sard appsec-out/benchmarks/sard-115 --out appsec-reports/benchmarks/javascript-ownership-sard
node bin/kayfabe.js benchmark cve-fixes appsec-out/cve-downloaded --out appsec-reports/benchmarks/javascript-ownership-cve
node scripts/score-supplied-apps.js appsec-out/supplied-benchmarks-2026-10-20/benchmarks/apps appsec-reports/benchmarks/javascript-ownership-after.json
node scripts/compare-javascript-ownership.js
```

The comparison script needs the previous full external reports under
`js-python-helpers-*` and the fresh supplied baseline
`javascript-ownership-before.json`. The supplied baseline was measured at
commit `ebb15d5772e03e985087631d1a3b4de98bc3e24d`; its source hash differs from
the previous published run because this Windows checkout uses different line
endings. Inputs, evaluator bytes, labels and outcomes match the committed
baseline. The comparison verifies those invariants and rejects stale final
source hashes, lost true positives and new false positives.
