# Independent baseline results and detection gaps

These are the original measurements. The subsequent
[precision changes and comparison](PRECISION-IMPROVEMENTS.md) retain these
baselines and report their own source hash and scoring policies.
Later [helper/sanitizer work](JAVA-HELPERS-SANITIZERS.md) and
[formatting-array work](JAVA-FORMAT-ARRAYS.md) also preserve these original
measurements. The [supplied apps](SUPPLIED-APPS.md) use a separate provisional
line-label policy.

Measured October 20, 2026, with Node 24.16.0 on Windows. All three runs used
harness source SHA-256
`8d6855a2374dd351e47d75a461636d391404c157a59f3f41f4649960b2713489`.
The detection rules were unchanged. These are separate measurements with
different scoring units; their totals must not be pooled.

| Dataset | Scored units | TP | FP | TN | FN | Recall | FPR | Precision |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Juliet Java 1.3 | 57,649 | 2,410 | 2,342 | 26,426 | 26,471 | 8.34% | 8.14% | 50.72% |
| NIST SARD suite 115 | 20 | 10 | 0 | 0 | 10 | 50.00% | n/a | 100.00%* |
| Eight real CVE pairs | 16 snapshots | 1 | 1 | 7 | 7 | 12.50% | 12.50% | 50.00% |

*SARD suite 115 has only vulnerable labels. Its precision cannot establish
false-positive performance. The CVE corpus has **0/8 successful complete
pairs**: no case both alerts on the parent and stays silent on the fix.

Checked-in evidence:

- [Juliet aggregate baseline](benchmarks/juliet-java-1.3-baseline.json):
  all 112 CWEs, coverage, label corrections, input and source hashes.
- [SARD baseline](benchmarks/sard-115-baseline.json):
  all 20 labeled locations and their outcomes.
- [CVE-fix baseline](benchmarks/cve-fixes-baseline.json):
  all eight pairs, revisions, original source hashes, and matching findings.

The Juliet aggregate omits the 57,649 individual units from the full 69 MB
report. Its artifact metadata retains the full report's SHA-256. Generate
the full reports using the [Juliet/SARD guide](JULIET-SARD.md) and
[CVE-fix guide](CVE-FIX-CORPUS.md). Target code was read statically; it was
not built or executed.

## Juliet: coverage and interpretation

All **28,881 upstream testcases** are represented. Each testcase contributes
one bad unit and, when explicit good regions exist, one good unit. There are
28,881 bad units and 28,768 good units; 113 testcases have no explicit good
regions. The scan read 46,803 Java files without file-count truncation.

The official manifest needs documented compatibility handling: two redundant
closing tags, 3,455 cases without flaw entries, and 15 flaw anchors attached
to explicitly good code. Three flaws use an exact-line fallback because no
recognized method encloses them. These counts and the overridden anchors are
in the baseline. This is corrected-label scoring using the upstream naming
conventions, not an unmodified NIST scorecard.

**106 of 112 CWEs have zero true positives.** Some are outside the scanner's
current rule set; others involve a source, flow, or CWE classification the
existing rules do not capture. Zero recall alone does not distinguish these
causes.

The largest zero-hit groups are:

| CWE | Vulnerable units missed | Current exact-CWE rule coverage |
|---|---:|---|
| 190 — Integer overflow | 4,255 | No registered rule |
| 191 — Integer underflow | 3,404 | No registered rule |
| 129 — Array index validation | 2,664 | No registered rule |
| 369 — Divide by zero | 1,850 | No registered rule |
| 789 — Excessive memory allocation | 1,571 | No registered rule |
| 400 — Resource consumption | 1,460 | No registered rule |
| 113 — HTTP response splitting | 1,332 | Registered rule is JS/TS, not Java |

These remain in the denominator. Supporting them requires additional analysis,
not merely enabling a current Java rule.

False positives are concentrated in four groups:

| CWE | TP | FP | Safe units | FPR |
|---|---:|---:|---:|---:|
| 89 — SQL injection | 1,820 | 1,820 | 2,220 | 81.98% |
| 78 — OS command injection | 444 | 444 | 444 | 100.00% |
| 601 — Open redirect | 44 | 44 | 333 | 13.21% |
| 327 — Risky cryptography | 34 | 34 | 34 | 100.00% |

Review the matching rules' handling of safe sources, guards, and method scope
before expanding these rules. Good and bad methods coexist in the original
source, and the scanner's taint analysis still sees that whole file. These
measurements identify the cases to inspect; they do not by themselves prove
which implementation change will fix them.

There are also 5,532 findings with other CWEs in labeled files and 17 outside
labeled files. They receive no scoring credit and are not automatically
additional false positives. Audit taxonomy differences, including the
CWE-80/81/83 XSS subclasses and CWE-23/36 path-traversal subclasses, before
considering any separately versioned alias policy. Do not relabel the baseline
to improve its score.

## SARD: ten missed PHP flows

All suite 115 cases use CWE-79. The following upstream cases were missed at
their explicit labeled locations:

| SARD case | Upstream flow description |
|---|---|
| 501059 | `__get__set` |
| 501060 | `return_reference` |
| 501061 | `environment_var` |
| 501065 | `subclass_getter` |
| 501070 | `singleton` |
| 501071 | `singleton_class` |
| 501073 | `singleton_set` |
| 501074 | `class_var_assign_string` |
| 501075 | `list_assignment` |
| 501077 | `global_variable` |

The baseline retains exact paths and lines. Review propagation through these
language constructs and whether a finding is reported at a different location.
The current scoring policy requires an exact labeled line or an explicitly
provided upstream range. Add independently labeled safe PHP cases before making
a false-positive claim. Other SARD suites and formats have not been measured
by this run.

## Real CVEs: source detection still falls short

PHPUnit CVE-2017-9841 is the only parent hit. Its fixed file also alerts:
the real patch changes input from the HTTP request body to CLI stdin, while
retaining `eval`. Review that distinction before changing the rule.

The seven missed parents are:

- PyYAML CVE-2020-14343 — CWE-20.
- EJS CVE-2022-29078 — CWE-74.
- Spring Framework CVE-2022-22965 — CWE-94.
- Werkzeug CVE-2024-34069 — CWE-352.
- Go crypto CVE-2024-45337 — CWE-1108.
- Jinja CVE-2025-27516 — CWE-1336.
- Next.js CVE-2025-29927 — CWE-285.

The corpus uses exact advisory CWEs, including several that differ from the
catalog's explanatory categories. It scans original affected source files,
without dependency manifests or full application context. Audit both
classification and framework-level data/control flows. A dependency advisory
hit cannot substitute for source detection in this corpus.

Parent/fix TP, FP, TN, and FN are scoped benchmark outcomes. A matching CWE
elsewhere in the changed file can be unrelated to the CVE. Narrower reviewed
regions and surrounding repository context are future improvements. The
remaining catalog CVEs have not yet been curated into this corpus.

## Next detection work

1. Investigate the high-FPR Java groups against both their vulnerable and safe
   variants. Keep the measured baseline immutable and record subsequent runs
   against the changed rules.
2. Inspect the ten missed SARD flows and the seven CVE parent misses using the
   recorded paths, labels, and primary patch evidence.
3. Separate unsupported weakness classes from classification and propagation
   failures before deciding which parser or taint changes to build.
4. Expand safe SARD examples and real CVE pairs, with explicit sampling,
   provenance, and scope. Validate on additional data before claiming that
   improvement generalizes.

This PR adds measurement and evidence. It does not close these detection gaps.
