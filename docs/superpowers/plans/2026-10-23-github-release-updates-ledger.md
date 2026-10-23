# Execution ledger — GitHub Release Updates

- Branch: `codex/release-update-check`
- Base commit: `051f3a9dae193d62b3f92ee09fe84909be011971`
- Plan: `2026-10-23-github-release-updates.md`
- Spec: `../specs/2026-10-23-github-release-updates-design.md`

Ruling: Do not add or run tests — the task instructions prohibit tests unless the user asks for verification, and Kayfabe's AGENTS.md prohibits executing repository code — implementation validation will be static review only; cost if wrong: regressions could escape until a later explicitly authorized verification run.

Task 1 implementation complete: `node --check src/update.js`, `node --check src/cli.js`, and `git diff --check` passed. No runtime or test commands were run.

Ruling: Regrade the reviewer's cache-write finding from Minor to Important because it undermined the once-per-day best-effort contract; add a per-user temp cache fallback and skip automatic requests when neither location is writable — cost if this regrade is too strict: automatic update discovery is skipped for users whose home and temp locations are both unwritable; explicit `kayfabe update` remains available.

Final review: the rest of the branch has no Critical or Important findings. Npm-install timeout was a recommendation, not a finding, and remains unimplemented because the release package is small and no timeout requirement was approved.

Ruling: Route automatic prompts and npm output to stderr, and skip prompts for `--quiet` — this preserves JSON/structured stdout and quiet-mode expectations — cost if wrong: users who expect update notices in stdout will instead see them on stderr, while command output remains parseable.

Post-fix verification: `node --check src/update.js`, `node --check src/cli.js`, and `git diff --check` passed. The modified cache fallback was reviewed statically; no Kayfabe commands or tests were executed.

## Merge compatibility review and installer hardening

The user's subsequent request to check compatibility and merge PR #28 authorizes scanner verification. PR #27 was merged first; the combined tree passed 391 tests and all 189 regression pairs. A fresh reviewer found that npm inherited the scanner's working directory and Git overrides, permitting a hostile local Git configuration to redirect the confirmed update. A local `git ls-remote --get-url` probe established URL expansion without any remote, helper or install execution.

The installer now uses a private temporary directory, an empty private Git config, a parent discovery ceiling, HTTPS-only transports, disabled hooks/fsmonitor/credential helpers and no inherited Git overrides. npm prefix settings remain unchanged. Cleanup runs after success and failure. Tests reproduced the isolation failure before the fix, then passed; further red/green tests caught the Windows null-device config and current-directory ceiling mistakes. Real Git URL expansion now preserves the canonical URL even beneath a hostile ancestor and with inherited `GIT_DIR`.

Final verification: 400/400 scanner tests and 189/189 regression pairs pass. Nine updater tests use mocked networking/installers; the Git integration check only expands a URL locally. The reviewer independently repeated the hardened-context probe on Git for Windows and found no remaining merge blocker. No real update installation, release endpoint request, target application or target test was run. README and AGENTS.md now document the updater network boundary. Real npm global installation and enterprise proxy/credential configurations remain untested; the original recommendation for an installation timeout remains deferred.
