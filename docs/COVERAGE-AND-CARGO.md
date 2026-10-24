# Analysis coverage and Cargo dependencies

Coverage is reported separately from severity. A severity gate passes when no finding meets its blocking threshold; it does not establish that the scanner supports the supplied code.

## Reading the report

Every new JSON report has `coverage` (`kayfabe/coverage@1`) and `dependencyInventory`. Human reports show analysis coverage next to the severity gate. SARIF stores coverage in run properties and execution notifications, without turning unsupported code into a vulnerability. JUnit adds an analysis-coverage suite: incomplete coverage is skipped by default, or failed when coverage is required. Reports from older scanners have unknown coverage.

| Section | What it measures | What it does not establish |
|---|---|---|
| Source | Available source checks ran on selected known source files | Exhaustive parsing, vulnerability coverage, runtime reachability or safety |
| Cargo inventory | Supported metadata was read; exact lock resolutions and manifest requirements are distinguished | That dependencies are installed, authentic, reachable, or consistent with a fresh Cargo resolution |
| Advisories | A limited curated database, plus opt-in OSV results if requested | Complete advisory coverage or absence of vulnerabilities |

Rust is recognized, but **Rust source analysis remains unsupported**. General secrets/configuration checks may still report candidates. C/C++, Swift, Dart, Lua, Perl, Elixir and Objective-C extensions are also explicitly unsupported by the source checks. Other unrecognized extensions may be unsupported; this is not an exhaustive language classifier. Existing C# parser coverage/fallback statistics remain separate.

The selected scope excludes default build/vendor directories, explicit excludes and tests unless `--include-tests` is given. Reports disclose these exclusions without counting their unvisited contents as analyzed. File size, depth/count limits, read failures, binary content in selected files and unfollowed links make coverage incomplete. This is conservative: an omitted non-source file can also make the scope uncertain.

```sh
node bin/kayfabe.js scan ./service --require-coverage --out reports/service
node bin/kayfabe.js report reports/service --require-coverage
node bin/kayfabe.js gate reports/service --require-coverage
```

`--require-coverage` adds a separate requirement: at least one selected source file, supported source checks for all selected known source files, no unintended omissions and no incomplete Cargo inventory. It does not require an exhaustive advisory database. Severity and coverage results are separately available as `gate` and `coverageGate`; CLI JSON also includes their combined result. `--no-gate` explicitly overrides exit enforcement. MCP `appsec_audit` and `appsec_report` accept `require_coverage` and return both gates and a combined `passed` result. Requiring coverage on a legacy report fails until it is rescanned.

## Cargo inventory

The scanner reads files without invoking Cargo, fetching dependencies, running build scripts or reading paths outside the selected target.

- `Cargo.lock` formats 2–4 provide exact package names, versions, source classes and SHA-256 checksums. A checksum is retained as metadata; the scanner does not download or verify package artifacts.
- A visible sibling lockfile, or a shared lockfile for a visible workspace member, takes precedence over manifest declarations. Lockfiles with unsupported syntax/identities produce diagnostics, not guessed resolutions.
- `Cargo.toml` entries without a lock are requirements, including bare `"1.2.3"` (Cargo interprets that as a range). They never become exact advisory queries or offline vulnerable-version findings.
- Renamed dependencies use the real package name while retaining the alias. Visible workspace declarations, explicit member locations and local path members can share a workspace lock and inherit dependency declarations. No Cargo resolver is implemented; features, platform selection and reachability are not evaluated.
- Registry, Git, local, root and workspace entries are distinguished. Root/workspace classification requires a matching visible package manifest. A sourceless entry without that evidence remains local/unknown; its path is not invented. Lock directness remains unknown rather than guessed.
- Source strings redact URL credentials and query values. Only the canonical crates.io registry identities are eligible for public advisory lookup. Private registry, Git and local package identities are excluded.

The bounded TOML subset supports basic/literal strings, integer/boolean scalars, arrays, inline tables, dotted keys, target tables and array tables. Multiline strings, floats/dates, duplicate/conflicting definitions, reserved prototype keys and unsupported dependency shapes produce explicit diagnostics. Limits are 1 MiB per document, depth 24, 250,000 parser items, 1,000 Cargo inputs and 16 MiB of Cargo input in total. Workspace glob matching uses bounded dynamic programming: `*`, `?` and whole-segment `**` are supported; character classes, escapes and out-of-target paths are diagnosed. Workspace matching has a shared one-million-operation budget, 128 patterns per list and 256 characters per pattern. These limits and syntax gaps can reduce inventory coverage. Source override declarations are not resolved from manifests and are reported incomplete; lock entries remain the authoritative observed resolutions.

## Advisory provenance and limits

The offline Cargo subset is dated **2026-10-24** and contains **one advisory**, `RUSTSEC-2024-0332` for `h2`. It is intentionally not described as a full RustSec snapshot. The source is pinned to RustSec/advisory-db commit `21d909e4c8bd4e14c7aea58bf980c881a0053ab1`; original advisory bytes, licensing and SHA-256 provenance ship in [provenance/rustsec](provenance/rustsec/). The dated OSV export is also preserved and hashed; its exact SemVer events, including prerelease boundaries, are checked against the shipped ranges. Derived summary, severity, CWE and version ranges are marked as derived in `src/supply/cargo-advisories.json`. Future entries require verified primary-source provenance before shipping.

With `--osv`, only exact public crates.io resolutions are queried. Cargo findings require matching advisory details; malformed responses, pagination or detail limits report an incomplete online query rather than claiming success. All advisory reporting remains limited, even when a query completes. A matching dependency is a component-level candidate, not evidence that a vulnerable API is called.

Official references: [Cargo requirements and renamed dependencies](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html), [shared workspace lockfiles](https://doc.rust-lang.org/cargo/reference/workspaces.html), [manifest versus lockfile](https://doc.rust-lang.org/cargo/guide/cargo-toml-vs-cargo-lock.html), [OSV querybatch and pagination](https://google.github.io/osv.dev/post-v1-querybatch/), [pinned advisory](https://github.com/RustSec/advisory-db/blob/21d909e4c8bd4e14c7aea58bf980c881a0053ab1/crates/h2/RUSTSEC-2024-0332.md).
