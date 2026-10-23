# GitHub release update checks

## Intent

Kayfabe users should hear when a newer stable GitHub Release is available and be able to install it from the CLI. Releases, including their notes, will be published on GitHub by a maintainer or coding agent. No release exists yet, so the feature must stay quiet until one is published.

## Goals

- Check the canonical `ray-goldman/kayfabe` GitHub Releases endpoint for the latest stable release.
- Tell interactive CLI users when a newer version is available, show the release notes link, and offer to install it.
- Provide a manual `kayfabe update` command for checking and updating on demand.
- Keep scans usable when GitHub is unavailable, and allow users to disable automatic checks.

## Non-goals

- Publishing a release, generating release notes, or changing the project’s release process.
- Publishing the private package to the npm registry.
- Updating prereleases automatically.

## Constraints

- Kayfabe is a Node.js CLI with no installed runtime dependencies and currently installs globally through `npm link`.
- `package.json` is marked private, but users can install a tagged GitHub repository with npm.
- GitHub release tags will be the version source; the release tag should match the package version, optionally prefixed with `v`.
- Automatic checks must be best-effort, throttled, interactive-only, and must not block normal use for long when offline.

## Approaches

1. **Install a GitHub release tag through npm (recommended).** Query GitHub Releases, then run the user’s global npm install for the exact release tag after confirmation. This fits the existing Node CLI and keeps release delivery on GitHub; it requires npm and Git on the user’s machine.
2. **Attach a package archive to every GitHub Release.** Kayfabe downloads and installs the archive itself. This avoids requiring Git, but needs a release asset build/publish step and more platform-specific replacement logic.
3. **Tell users to update their source checkout manually.** This has little implementation cost but does not meet the one-step update goal and can conflict with local edits or branches.

The current proposal selects approach 1 because it uses the existing npm-based command installation while keeping release artifacts and notes on GitHub.

## Proposed behavior

- On interactive command invocations, perform a throttled release check and ask before installing a newer stable release. Non-interactive invocations never prompt.
- `kayfabe update` checks and offers the same install action; a check-only option reports the available version and release URL without installing.
- No release, an unavailable network, malformed release data, or an unsupported local install must not prevent the requested scan or command from running.
- Provide an environment variable to disable automatic checks. Do not send credentials or repository contents to GitHub.

## Open implementation choices

- Choose a short network timeout and a once-per-day cache window.
- Keep release note display concise and link to the full GitHub release.
- Detect and report when npm or Git is unavailable instead of attempting a partial install.
