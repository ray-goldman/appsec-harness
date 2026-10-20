# Juliet, SARD, and CVE-fix measurements

## Goal and scope

Continue priority 1 after PR #1: add repeatable measurements on Juliet Java,
selected NIST SARD data, and real upstream CVE parent/fix revisions. Preserve
the existing OWASP evaluator and detection rules. Report misses and residual
alerts without tuning rules to these measurements.

## Design

The existing scanner remains the source of findings. Separate adapters define
the scoring unit and consume independent labels:

- Juliet Java 1.3: distinguish good and bad method regions within the same file.
  Use the suite's naming conventions and upstream labels; document wrapper,
  helper, and cross-file limitations.
- NIST SARD: consume native SARIF manifests and their explicit CWE/location
  labels. Missing negative labels do not imply safe code. Undefined rates are
  null, displayed as n/a.
- CVE fixes: maintain a manifest of catalog CVEs with primary references,
  verified first-parent/fix commits, source paths, and byte hashes. Download
  immutable source files in an explicit preparation step; evaluate offline.
  Count vulnerable detection and fixed silence separately, plus successful pairs.

Use full source files for each selected CVE change, preserving upstream paths
inside isolated revision snapshots. This measures the selected source scope;
it does not prove whole-repository accuracy or deployment exploitability.

## Global constraints

- Node.js 20 or newer, zero runtime dependencies.
- Read target repositories as data. Do not execute their code or build scripts.
- Keep datasets and full generated reports in ignored output directories.
- Keep all declared labels, including unsupported CWEs, in the denominator.
- Fail on missing, linked, changed, binary, or scanner-skipped labeled inputs.
- Record input/label hashes, scanner options, policy, and harness source hash.
- Outputs must stay outside datasets; replace report files atomically.
- Do not add or run implementation tests unless requested. The requested real
  benchmark measurements are deliverables.

## Tasks

1. Confirm merged base, create feature branch, and expose existing benchmark
   safety/hash/report helpers.
2. Add Juliet/SARD adapters and measure the official archives. Record exact
   support boundaries and per-CWE outcomes.
3. Add curated real CVE manifest, explicit pinned fetcher, offline pair scorer,
   and provenance documentation. Measure every included pair.
4. Integrate CLI commands and reproduction guides. Commit aggregate baselines,
   update roadmap and README, and review the complete diff.
5. Push a review branch and open a draft PR. Keep merge under user control.

## Review focus

- Mixed safe and unsafe regions must not collapse into a file-level prediction.
- Missing negative labels must not manufacture true negatives.
- Skipped files and unsupported CWEs must not inflate recall.
- Hostile manifests must not escape paths or cause execution/network requests
  during measurement.
- CVE fixes must be real upstream changes with correct first-parent ancestry;
  fixed silence must be judged only against the declared source/CWE scope.

## Progress

- Confirmed PR #1 merged at `ff10c2d1911fd57932edecb0e3b782462e5d346a`.
- Official NIST suite 111 and 115 downloads match NIST's published SHA-256.
- Juliet/SARD implementation and CVE provenance/runner delegated with disjoint
  file ownership. Root owns shared exports, CLI, aggregate baselines, and guides.
- Completed the full Juliet run: 28,881 upstream cases, 57,649 polarity units,
  112 CWEs, TP 2,410 / FP 2,342 / TN 26,426 / FN 26,471.
- Completed SARD suite 115: 20 bad locations, TP 10 / FN 10; no negative labels.
- Downloaded 28 original files for eight CVE pairs through the explicit fetcher.
  Completed offline measurement: TP 1 / FP 1 / TN 7 / FN 7; zero successful pairs.
- All three baselines share source hash
  `8d6855a2374dd351e47d75a461636d391404c157a59f3f41f4649960b2713489`.
  Case outcomes were independently recounted and reconcile with per-CWE totals.
- Added three baseline JSON artifacts, reproduction guides, and a detection-gap
  report. Source review found no remaining blockers; corrected the documented
  revision option to `--dataset-revision`.
- No detection-rule changes or implementation tests were added or run. Validation
  evidence consists of the real requested measurements, static review, byte/hash
  checks, reconciled counts, and whitespace review.
