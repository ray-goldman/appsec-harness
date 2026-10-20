# JavaScript and Python helper precision

This pass starts with a [review of 11 supplied safe labels](SUPPLIED-HELPER-LABEL-REVIEW.md).
The original labels, input bytes, scorer and denominators are retained. The
supplied applications are regression material, not held-out accuracy evidence.

## Final measurements

| Dataset / policy | Cases | TP | FP before → after | TN | FN |
|---|---:|---:|---:|---:|---:|
| OWASP Java 1.2 | 2,740 | 571 | 289 → 289 | 1,036 | 844 |
| Juliet Java 1.3 | 57,649 | 2,410 | 1,172 → 1,172 | 27,596 | 26,471 |
| SARD 115 vulnerable locations | 20 | 10 | 0 → 0 | 0 | 10 |
| CVE historical file+CWE | 16 | 1 | 1 → 1 | 7 | 7 |
| Supplied application line labels | 227 | 81 | **16 → 14** | 76 | 56 |

All four external benchmark case outcomes are unchanged. The supplied suite
has exactly two FP→TN transitions and no other outcome changes:
`xfile-lab/py/views.py:46:validated-by-guard-helper` and
`xfile-lab/py/views.py:76:int-cast-then-format` (IDs use marker lines).
Across all five suites there are **zero lost previously detected true positives
and zero new false positives**.

Supplied-label FPs fall **12.5%**. Its provisional FPR is **17.78% → 15.56%**
and precision **83.51% → 85.26%**; recall stays **59.12%**. Labels are unchanged,
including shell-quoting labels with platform qualifications. The 54 manifest
labels remain unscored, and unmatched findings remain unclassified.

Historical CVE scoring remains **0/8 complete pairs**; the separate localized
policy remains **1/8**, with TP=1, FP=0, TN=8 and FN=7. SARD has no safe labels,
so its FPR remains undefined. This pass does not improve the missed CVE parents
or establish production precision.

Final evidence:
[case comparison](benchmarks/js-python-helpers-comparison.json),
[OWASP](benchmarks/owasp-java-1.2-js-python-helpers.json),
[Juliet](benchmarks/juliet-java-1.3-js-python-helpers.json),
[SARD](benchmarks/sard-115-js-python-helpers.json),
[CVE](benchmarks/cve-fixes-js-python-helpers.json), and
[supplied apps](benchmarks/supplied-apps-js-python-helpers.json).

Every final run used source SHA-256
`27e350e92d407e71dbd7af4ffa31b0a717dfcc73e820306f78d20062dad92ba7`,
on October 20, 2026, with Node v24.16.0 on Windows. The recorded scan phases
were 15.4 seconds for OWASP and 189.9 seconds for Juliet, versus 13.7 and 190.4
seconds previously. These concurrent, uncontrolled measurements exclude
preparation and report writing; they do not establish a performance change.

## Scope of the proof

The scanner reads admitted local `.js` and `.py` files without importing or
executing them. A bounded proof can suppress an existing SQL or command
candidate. It does not change general taint propagation.

Numeric SQL requires an adjacent assignment and an unquoted numeric SQL
position. The conversion must resolve to `Number` or `int`, or a local helper
whose body returns that conversion of its single parameter. Helper names alone
carry no trust. JavaScript uses a local `const`; Python rejects module-level and
global/nonlocal bindings. Shadowed conversions, intervening statements,
additional arguments and unsupported expressions retain warnings.

The Python hostname guard resolves a local module and a single function body.
The body must use `re.fullmatch` with the bounded ASCII hostname character set,
and the caller must return on failure before concatenating the checked variable
into the command. The proof is for shell metacharacters (CWE-78); leading
hyphens can still matter to command options (CWE-88).
The value must come from the modeled Flask request-string source, directly or
through a resolved helper. Arbitrary wrappers and overloaded string operators
are unsupported; passing a regex does not establish safe object concatenation.

Dynamic namespaces, ambiguous modules, visible helper replacement, unsupported
syntax and incomplete source inventories make the proof unknown. JavaScript
helper modules use a deliberately small CommonJS export form. Python helpers
use a plain module import and a single return expression. This does not provide
a general cross-file call graph, runtime import resolution or an effect system.
Other scanner-supported script extensions that this index cannot analyze make
the inventory incomplete. Decorated helper modules and non-ASCII Python
identifiers are unsupported rather than guessed through.

JavaScript proofs also reject bracket syntax anywhere in the admitted JS
sources. This prevents computed constructor/global access from bypassing binding
checks, but also rejects ordinary arrays and computed lookups. Imported
CommonJS helpers require a closed set of supported local imports and exactly
one importer of the helper module; unresolved paths and cached-export sharing
remain unknown. These restrictions leave the supplied JS numeric case flagged.
The ordinary built-in/runtime and Flask source models are static assumptions;
this pass does not verify installed dependency behavior or runtime monkeypatches
outside the scanned source inventory.

Index limits are 2,000 files, 8 MiB total and 100,000 characters per file. Proof
attempts are capped at 128 per scan. Single-line sinks are capped at 2,000
characters and numeric expressions at 1,000. Budget exhaustion retains alerts.

POSIX quoting with an implicit shell, mutable configuration exports, JavaScript
hostname coercion and general path confinement remain unsupported. Missing
source and dynamic behavior can prevent otherwise safe cases from being proved.

## Reproduction

```sh
node bin/kayfabe.js benchmark owasp-java appsec-out/benchmarks/owasp-java --out appsec-reports/benchmarks/js-python-helpers-owasp
node bin/kayfabe.js benchmark juliet-java appsec-out/benchmarks/juliet-java-1.3/Java --out appsec-reports/benchmarks/js-python-helpers-juliet
node bin/kayfabe.js benchmark sard appsec-out/benchmarks/sard-115 --out appsec-reports/benchmarks/js-python-helpers-sard
node bin/kayfabe.js benchmark cve-fixes appsec-out/cve-downloaded --out appsec-reports/benchmarks/js-python-helpers-cve
node scripts/score-supplied-apps.js appsec-out/supplied-benchmarks-2026-10-20/benchmarks/apps appsec-reports/benchmarks/js-python-helpers-after.json
node scripts/compare-script-helpers.js
npm test
node bin/kayfabe.js selftest
```

The comparator checks dataset and label hashes, policies, every case transition,
lost true positives and newly introduced false positives. The four external
baselines are the prior formatting-array reports. The supplied baseline was
remeasured before these changes on commit
`a99906e964898e87fd5826cd783069bfaed8f016`; its scanner byte hash differs from
the pre-rename runs. Original reports are preserved.
The supplied evaluator also has a CRLF byte hash in this checkout. The
comparator requires identical evaluator bytes before/after, and verifies that
normalizing CRLF to LF reproduces the prior committed evaluator hash exactly.
The fresh baseline's complete per-app results match the prior baseline.

## Review and regression verification

Two independent reviewers examined the implementation sequentially, each with
a fresh context. Their probes scanned temporary source fixtures without
executing them.

The first pass found loader shadowing, numeric builtin replacement in another
module and regex-function mutation. Follow-up checks covered tuple and
parenthesized helper stores, unsupported script extensions and uppercase
extensions. The scanner now rejects these uncertain bindings. The reviewer
verified the original and related reproducers and reported no remaining
actionable findings.

The second pass found multiline decorators, overloaded string concatenation,
computed global writes and Python identifier normalization. Follow-up checks
found computed constructor access and cached helper-export mutation, including
an importer with an unsupported parent-relative path. The fixes narrow accepted
source types, reject unsupported lexical/dynamic constructs, and require
exclusive, fully resolved local imports for CommonJS helper summaries. The
reviewer independently verified all seven reported reproducers after the fixes.

The focused tests include positive helper cases and negative controls for the
review findings. **172 tests and all 151 vulnerable/fixed corpus pairs pass.**
These tests were developed with the implementation; their scores describe
regression coverage.

The early candidate removed three supplied-label false positives. That result
was superseded: the final bracket-syntax restriction restores the JS warning,
leaving two supported Python corrections. Benchmark runs begun before review
fixes are superseded by the final runs.

## Remaining work

1. Establish explicit shell and argument-type guarantees before handling the
   remaining JavaScript guard and JS/Python shell-quoting labels. Keep command
   option injection separate from shell metacharacter injection.
2. Model module initialization, export ownership and effects before borrowing
   mutable configuration values. A constant-looking name is insufficient.
3. Review the supplied HTTP allow-list labels against redirects and deployment
   behavior. The unresolved labels must not become blanket SSRF suppressions.
4. Extend helper summaries to general flows only with scope, dispatch and effect
   evidence. This pass leaves many valid but unsupported forms flagged.
5. Keep the missed vulnerable labels visible: helper precision alone does not
   recover missing detections. Broader CVE mechanisms, negative SARD examples and
   held-out applications remain separate priorities.
