# MCP file confinement: verification and self-audit

The October 23, 2026 self-audit confirmed that a local target's directory junction could redirect MCP source reads and triage evidence outside the selected root. The old code checked the lexical path and leaf only. This was a manually discovered high-severity finding; the scanner did not detect it.

## Change

One reader now checks every descendant component and canonical containment, reads through a verified descriptor, bounds the bytes read, checks observed path/content changes and closes the descriptor on every outcome. MCP source reads/search, triage previews and every evidence channel use it. Supported paths and portable filesystem limits are documented in [FILE-CONFINEMENT.md](FILE-CONFINEMENT.md).

## Verification

- Clean base: 400 tests passed.
- Original public-API regression run before the fix: 10 tests, 3 passed, 6 failed, 1 skipped. Failures reproduced the directory-junction escape and related boundary behavior.
- Final Windows run: 419 tests, 416 passed, 0 failed, 3 skipped. The 19 new tests contributed 16 passes and the 3 explicit Windows skips.
- Corpus regression suite: all 189 vulnerable/fixed pairs passed, with 100% recall and precision on that self-authored suite.
- The controlled dummy junction probe now rejects the outside read and outside evidence; ordinary source reads and evidence remain valid. No real secrets or target application code were used.

The Windows skips are the privileged leaf-symlink case and two rename-while-open cases Windows blocks. The Linux CI job runs the same suite and must exercise those branches before merging. A failed mutation setup cannot satisfy the mutation regressions: the tests require the setup to finish, or explicitly report the supported Windows skip.

## Self-audit comparison

Both scans used the default scanner configuration, with automatic update checks and OSV requests disabled. The production profile additionally excluded `corpus,test,docs,benchmarks`; the full profile retained the usual default exclusions. No dependency installation or actual updater installation ran.

| Measurement | Before: main `8d3ffb9` | After: implementation `26339dd` |
|---|---:|---:|
| Production raw candidates | 24 | 24 |
| Full-default raw candidates | 328 | 328 |
| Full-default candidates in inert corpus files | 307 | 307 |
| Triage coverage, both profiles | 100% | 100% |
| Manually confirmed open high findings | 1 | 0 |
| Final gate, both profiles | FAIL | PASS |
| Junction permits outside source read/evidence | Yes / Yes | No / No |

The 24 production candidates remain 17 operator-path warnings in standalone CLI benchmark utilities, 4 expected agent/MCP configuration warnings and 3 logging warnings on scanner metadata/regex declarations. The full scan has 21 non-corpus candidates because project-wide logging context differs. These are the same candidate identities and source bytes as the baseline; those assertions were checked before reusing their scoped dispositions.

The 307 corpus candidates are intentional static fixtures, reviewed as data and dismissed only for production exploitability. They are not counted as 307 false positives in an accuracy benchmark. The fixed high finding was retired using manual review, regressions and the controlled probe; no scanner-detection improvement is claimed. Detection rules, benchmark labels and accuracy scorers did not change.

## Frozen provenance and retained evidence

Measured implementation commit: `26339ddbec30d0f87eaf3d0d5e7591db1ea4a2ad`.

- Git tree: `2a06e2e6055cc52d5614028bbaedb285f097fe4c`.
- Package version: `1.0.0`.
- Scanner source SHA-256: `47d9d1d138be4f75eb9f1ccf15dec8b02322e72b47141db3227de1448dd37917`.
- 957 archived tracked files verified against Git, normalizing CRLF to LF only for comparison. The manifest records hashes of the exact scanned bytes.

The local evidence directory `output/mcp-confinement-2026-10-23` contains the frozen source archive, exact-byte manifest, controlled probe, triage, validation logs, final JSON/SARIF/JUnit/HTML reports, test logs and review artifacts. The previous `output/kayfabe-self-audit-2026-10-23` evidence, including the original escape probe, is preserved. Paths are relative to the parent workspace; generated target snapshots and reports are not committed to the source repository.

This document and subsequent review notes summarize the frozen implementation. They were added after that snapshot; the snapshot does not claim to contain later documentation commits.

## Reviews

Pass 1 found no important implementation issue. Its minor test finding was fixed: duplicate-evidence and search-swap regressions now assert that their junction mutation completed, rather than allowing a setup exception to look like a protected read.

Pass 2 found no actionable issue. The fresh reviewer reran all 19 focused tests (16 passed, 3 explicit Windows skips), independently verified all 957 frozen files against Git and the exact-byte inventory, checked archive/inventory/scanner hashes and unchanged candidate/source identities, and verified 100% triage coverage and both passing gates. Both reviews used fresh contexts with the code and stated requirements available; they are code reviews, not independent benchmark authorship.
