# Rust coverage and Cargo inventory results

Measured 2026-10-24 against main `f897bf83bec8fbdaa99f320fc1849529cfaeeb08`. Final measured implementation: `3485ac6c56752a71bc96ee7b26ab358f45ebdbde`. See [the aggregate and provenance](benchmarks/rust-cargo-coverage-results.json) and [coverage policy and parser limits](COVERAGE-AND-CARGO.md).

## What changed

Reports now distinguish source analysis, dependency inventory and advisory checks. Rust files are recognized but remain unsupported for source analysis. `--require-coverage` enforces a separate requirement alongside the existing severity gate. Cargo lockfiles provide exact package inventory; manifest requirements remain unresolved requirements. Public crates.io resolutions support opt-in OSV queries, and a dated offline subset contains one verified RustSec advisory.

## Hermes development pair

Both frozen source variants were rescanned in default and optional project profiles. Every extracted byte was checked before and after scanning. Each variant has one Rust source file and 265 lockfile package entries, including its local root.

| Measurement, each variant/profile | Before | After |
|---|---:|---:|
| Rust files recognized | 0 | 1 |
| Rust files analyzed by source rules | 0 | 0 |
| Lock package entries inventoried | 0 | 265 |
| Public registry entries inventoried | 0 | 264 |
| Automated findings | 0 | 0 |
| Source coverage | Unknown | Incomplete |
| Cargo metadata coverage | Unsupported | Complete within the supported subset |

The severity gate passes for both variants because no blocking automated finding was emitted. Requiring coverage fails because Rust source analysis is unsupported. Zero findings receive no true-negative credit. There is no frozen vulnerability answer key for this pair, and the code has already been inspected; no blind or independent accuracy score is assigned. Earlier manual review findings receive no automated detection credit.

Archive SHA-256: `7fc26cf18d10eaac432dc7b1028b1d176570b23b7a8d9288972e3e886a8fea26`. Eighteen extracted files were verified. The supplied executable remained inside the original ZIP and was not extracted or run.

## Established benchmarks

Every scored decision is unchanged. Counts below apply to both baseline and final candidate; datasets retain their original policies and are not pooled.

| Dataset | Units | TP | FP | TN | FN |
|---|---:|---:|---:|---:|---:|
| Juliet C# 1.3 | 59,282 | 1,036 | 470 | 29,131 | 28,645 |
| OWASP Java | 2,740 | 571 | 289 | 1,036 | 844 |
| Juliet Java 1.3 | 57,649 | 2,410 | 1,172 | 27,596 | 26,471 |
| SARD PHP 115 | 20 | 10 | 0 | 0 | 10 |
| Original CVE-fix policy | 16 | 1 | 1 | 7 | 7 |
| Supplied application labels | 227 | 87 | 11 | 79 | 50 |
| Earlier supplied .NET labels | 230 | 32 | 1 | 90 | 107 |

The original CVE pair policy remains 0/8; the separate localized policy remains 1/8. Neither improves in this change. Full Juliet C# recall remains 3.49%; this inventory/coverage work does not improve existing source detection or reduce established false positives. The earlier [measured .NET limits](STATUS-AND-COMPARISON.md) still apply.

Input, label, unit-manifest, scoring-policy and evaluator identities were compared. Twenty-six evaluator/policy files were also compared byte-for-byte between archived scanners. The C# scan-duration ratio was 0.939 against a maximum acceptance ratio of 1.5. These were single concurrent runs on a shared machine; no speedup is claimed.

## Frozen and real-code replays

- Safe-only C#: 0 false positives and 20 true negatives in each profile; recall is undefined because no vulnerable cases are labeled. Twelve native C cases remain unsupported and earn no true-negative credit.
- Earlier frozen C#: 2 TP, 0 FP, 20 TN and 8 FN in each profile; 18 native C cases remain unsupported. Original archives, answer keys, scoring policy and adjudications were retained.
- FinSuite: zero raw candidates in both profiles, unchanged. This is not proof that the application is secure.
- Nine development apps: identical finding identities, retaining 18 adjudicated true positives and 10 false positives per profile. Remaining unclassified/review candidates were not relabeled.
- Previously pinned nickrulez and blesclues checkouts: respectively 9 and 36 candidates per profile, with identical finding identities. These are compatibility replays, not new independent accuracy estimates.
- All 190 prior adversarial fixtures retain identical finding identities.

## Tests, reviews and advisory checks

The exact final Windows archive passed 551 tests, with zero failures and three explicit platform skips (554 total). All 193 vulnerable/fixed regression pairs passed. These pairs are self-authored regression coverage, not independent accuracy evidence.

Two fresh code review passes found and closed issues in workspace glob bounds, post-budget processing, inherited local paths, incomplete metadata diagnostics, TOML table conflicts and inventory redaction. Follow-up probes verified the corrections. Source redaction now uses bounded authority parsing; a long malformed source value cannot trigger the earlier unanchored search. URL userinfo, nested metadata and file-level detected secrets are withheld from inventory output.

The offline Cargo subset is pinned to verified RustSec bytes and a hashed OSV export. Tests check its exact prerelease boundaries and vulnerable/fixed versions. A real OSV smoke test queried only the scanner-owned public `h2@0.3.25` fixture, producing three online advisory candidates. Supplied app identities, code and findings were not sent. A recognized secret disguised as a Cargo package identity stops online lookup before any request.

Intermediate candidates were retired after review/self-review corrections: `4222a92` (first review/provenance), `19b1147` (second review), `070a8d4` (online identity privacy), and `c88f623` (redaction resource bound). Their local evidence was preserved. Final acceptance uses `3485ac6` only; no benchmark key, label, policy or scorer was tuned after inspecting results.

## Remaining work

Rust source rules still need a bounded lexical/syntax and API-ownership model. Cargo parsing supports a documented subset rather than Cargo resolution, feature evaluation, reachability or artifact verification. The offline database contains one advisory and is not a complete RustSec/GHSA snapshot. Existing source-analysis misses and false positives remain. No competing-scanner head-to-head or production accuracy estimate has been established.

All target evaluation was static. No target builds, tests, scripts, binaries, Cargo commands or dependency installs ran. Published evidence contains sanitized aggregates and scanner-owned/public regression inputs; supplied source and answer keys remain local.
