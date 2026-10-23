# GitHub Release Updates Implementation Plan

> **For agentic workers:** Follow the approved design in [the spec](../specs/2026-10-23-github-release-updates-design.md). Implement the steps in order.

**Goal:** Let Kayfabe users discover stable GitHub Releases and install a selected release from the CLI.

**Architecture:** Add a focused `src/update.js` module for release lookup, version comparison, check throttling, user confirmation, and npm installation from the exact release tag. Integrate it into `src/cli.js` for interactive startup prompts and `kayfabe update`; keep update failures best-effort for normal commands.

**Tech Stack:** Node.js 20+, built-in `fetch`, `readline/promises`, `fs`, `os`, `path`, and `child_process`; no new dependencies.

**Spec:** `docs/superpowers/specs/2026-10-23-github-release-updates-design.md`

## Global Constraints

- Use the GitHub stable release endpoint for `ray-goldman/kayfabe`; the release tag must match the package version with an optional leading `v`.
- Keep automatic checks interactive-only, at most once every 24 hours, and bounded to a 2-second request timeout; use a temporary cache fallback and skip auto-checking if no cache is writable.
- A missing release, network failure, invalid release response, or unavailable installer must not prevent an ordinary Kayfabe command from running.
- Never install without a user's affirmative confirmation; `--yes` applies only to the explicit `kayfabe update` command.
- Do not add installed runtime dependencies or send repository contents or credentials to GitHub.
- Per the task instructions, do not add or run tests unless the user asks for verification.

## Review Focus

- No release exists yet: the check must quietly treat GitHub's not-found response as “no update.”
- A release tag is external input: reject tags that are not valid stable versions before using one in an install command.
- A user has no TTY or has disabled checking: normal commands must not prompt or wait on a release request.
- A command writes JSON/structured output or uses `--quiet`: update messages must not corrupt stdout or violate quiet mode.
- GitHub is offline or slow: normal command execution must continue after the timeout and update-check failures must not recur on every invocation.
- npm or Git is unavailable, or the user declines: report the outcome without claiming an update succeeded or interrupting the requested scan.

---

### Task 1: Implement GitHub release discovery and install flow

**Files:**
- Create: `src/update.js`
- Modify: `src/cli.js`
- Modify: `README.md`

**Interfaces:**
- `src/update.js` exports `checkForUpdate({ force = false } = {})`, resolving to `{ status, currentVersion, release }`, where `status` is `available`, `current`, or `unavailable`; `release` is `{ version, tag, name, url }` when GitHub provides a valid latest release.
- `src/update.js` exports `installRelease(release)`, which installs the exact validated GitHub tag globally through npm without a shell; it returns `{ ok, message }` and never treats a failed npm/Git invocation as success.
- `src/cli.js` owns command routing and invokes update checks only after parsing arguments and confirming an interactive terminal.

- [x] Implement strict stable-version parsing/comparison and GitHub latest-release lookup in `src/update.js`; use a 2-second timeout, reject redirects, validate response fields and the `html_url` host, and distinguish available, current, and unavailable outcomes.
- [x] Add a home-directory check cache plus a per-user temp-directory fallback in `src/update.js`; record attempts so failed checks are throttled too, skip automatic networking if neither cache is writable, and make `force: true` bypass the automatic 24-hour cache.
- [x] Implement `installRelease(release)` with argument-array process execution, passing npm a fixed GitHub repository plus the validated tag. Handle Windows npm CLI discovery without interpolating untrusted input into a shell command.
- [x] Add interactive update prompts to `src/cli.js` for eligible commands; print the current and available versions plus release URL to stderr, ask before installation, route automatic installer output to stderr, and continue the requested command if the check fails or the user declines. Skip prompts when stdin/stderr are not TTYs, `--quiet` is set, or `KAYFABE_NO_UPDATE_CHECK` is set.
- [x] Add `kayfabe update`, `kayfabe update --check`, and `kayfabe update --yes`. The default checks and asks before installing; `--check` reports the available/current/unavailable status without installing; `--yes` confirms installation for this explicit command. Keep `update` out of the startup prompt path to avoid duplicate checks and reject `--check` combined with `--yes`.
- [x] Update CLI help and `README.md` with automatic-check behavior, disable environment variable, manual update commands, and the Git/GitHub install requirements.
- [x] Review the diff and branch status for accidental changes outside the updater, CLI, README, and this plan/spec.
