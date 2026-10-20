# Supplied application baseline

The October 20, 2026 attachment contains 13 small applications with planted
vulnerabilities and safe examples. We scanned their source without building,
installing or running them. Scripts and instructions inside the archive were
treated as input data. The archive's README says the apps were developed
alongside the rules; these measurements are regression evidence, not held-out
accuracy evidence.

Archive: `appsec-benchmarks.zip`

SHA-256: `3dab4cfd405e313ed80093560c3bf17cfb6f4ae5a33902da43a3054af9878c25`

The original archive, extracted sources and detailed local reports stay outside
Git. The committed report contains labels, locations and rule IDs, without
source snippets. It is separate from the OWASP, Juliet, SARD and CVE reports.

## Scoring policy

The harness-owned [evaluator](../scripts/score-supplied-apps.js) reads `BENCH`
comments as proposed labels. A finding needs the same file and exact CWE, at
the first line after the marker or the next two lines. The nearest eligible
marker receives the finding; one finding cannot credit several labels.
Duplicate findings do not inflate detected-case counts.

This differs from the archive's scorer, which accepts an OWASP-category match
even when the CWE differs. We did not execute that scorer or adopt its saved
results. Neither policy is equivalent to whole-file OWASP matching or Juliet
method-unit matching. Line windows can miss correctly detected issues reported
at a different location.

All 227 line labels are counted: 137 vulnerable and 90 safe. The 54 manifest
labels are explicitly **unscored**, pending an adapter that can resolve package,
version and advisory identity. All 13 apps, including the dependency-only app,
are still scanned. Findings without a compatible line label remain unclassified;
they are not automatically false positives.

Labels have not undergone full independent adjudication. “FP” below means
“finding matched a supplied safe label,” not a confirmed scanner error.

## Initial measurements

| App | TP | FP | TN | FN |
|---|---:|---:|---:|---:|
| dotnet-hr | 3 | 0 | 7 | 11 |
| go-api | 8 | 3 | 3 | 1 |
| infra-mixed | 9 | 1 | 4 | 4 |
| java-bank | 7 | 1 | 4 | 2 |
| node-design-lab | 3 | 0 | 5 | 10 |
| node-shop | 14 | 2 | 10 | 0 |
| php-blog | 6 | 0 | 9 | 3 |
| py-design-lab | 2 | 0 | 4 | 8 |
| py-notes | 11 | 1 | 8 | 0 |
| ruby-forum | 4 | 0 | 9 | 10 |
| ts-react-portal | 8 | 1 | 7 | 4 |
| xfile-lab | 6 | 7 | 4 | 3 |
| deps-lab | — | — | — | — |
| Total | **81** | **16** | **74** | **56** |

These provisional counts imply 59.12% recall, 17.78% FPR and 83.51% precision
within this label set. They must not be described as production accuracy.
The dependency app produced 23 findings; its 34 manifest labels are among the
54 unscored labels.

The [before/after report](benchmarks/supplied-apps-format-arrays.json) retains
all line cases and unmatched finding locations. Input and evaluator hashes,
all cases, matches and unmatched findings are identical before and after the
Java formatting-array change.

The initial app scan was taken from merged `main` commit
`4a3ad834a02995ccd4acd20230dff7a5cb47ae73`, with byte hash
`d1c1bb209303c475a5130d0cf7e5a478ea9e23820bf88248c48e2864a3ae9be4`.
That hash was reproduced from the pre-change Windows checkout contents.
It differs from the earlier four-suite report hash; each measurement retains
its actual source identity rather than substituting another run's hash.

## What to investigate next

Seven of the 16 flagged safe labels are in `xfile-lab`: shell quoting,
hostname guards, constants imported from another file, and numeric SQL values.
These give concrete targets for source-to-sink helper analysis in JavaScript
and Python. Safe helper names alone must never suppress warnings: this app
also contains misleading sanitizer names that merely trim input.

Other candidates include Java's `normalize`/`startsWith` path guard, Go's
argument-vector command invocation and basename handling, and a workflow that
passes the pull-request title through an environment variable.

Four safe labels in Go, Node, Python and TypeScript concern HTTP allow-lists.
Their code validates the initial destination but does not show an explicit
redirect restriction. Keep the labels and measured counts unchanged while
reviewing client redirect behavior and deployment assumptions. Do not teach
the scanner that any hostname check proves SSRF safety.

The supplied labels also expose misses in business logic and cross-file flows,
particularly the design-lab, C# and Ruby apps. No application-specific rule
exceptions were added in this pass.

## Reproduce

After extracting the attachment into a confined local directory:

```sh
node scripts/score-supplied-apps.js appsec-out/supplied-benchmarks-2026-10-20/benchmarks/apps appsec-reports/benchmarks/supplied-apps.json
```

The report hashes every input file, the evaluator, and the scanner. The source
is never imported as a module or executed. Keep the archive hash alongside
the report when sharing results; the source archive is not redistributed by
this repository.
