# Confined MCP source reads and triage evidence

The user approved fixing the directory-junction escape demonstrated by the October 23 self-audit, adding regressions, rerunning tests and the self-audit, and completing two reviews before opening a PR.

## Contract

One shared reader must protect MCP source reads, search results, triage context previews and all triage evidence locations. File arguments are relative to the selected audit root. Ordinary nested files and a user-selected root alias remain readable. Descendant directory junctions/symlinks are rejected even when their destination is inside the root; leaf links, outside paths, invalid inputs, directories and unreadable/missing files are rejected. Additional-findings locations receive the same validation as verdict evidence.

Canonicalize the root, enforce canonical containment, and inspect every descendant component. Read through a verified descriptor with file identity checks rather than reopening the pathname after checking it. Recheck path/root identities around opening and reading; reject observed mutations and changed content. Close descriptors on every outcome. Use no installed dependencies or target execution. Keep reads bounded to the scanner's default 1 MiB source-file limit.

This is a portable Node.js guard, not an atomic `openat2`/directory-handle sandbox. Checks and descriptor identity protect against static links and observed changes; arbitrary repeated adversarial filesystem mutation cannot be proven impossible with portable path APIs. Use stable snapshots for hostile input. Pre-existing hard links are regular files and are outside this directory-link guarantee. Document these limits without claiming a fully race-free filesystem sandbox.

## Acceptance

- The original controlled junction probe is refused by both MCP reads and evidence validation; no outside marker is returned.
- Direct/ancestor links, in-root links, prefix siblings and every evidence channel fail closed; ordinary files still work.
- Triaging/searching a target whose files become linked does not expose outside context.
- Deterministic rename/link swaps and descriptor mismatches are refused before outside bytes are read; descriptors close after success and errors.
- Full scanner tests and all 189 corpus pairs pass. Self-audit dispositions are rechecked against the changed source; the former high finding is retired only with the regression/probe evidence.
- Two fresh review passes complete before the PR, with important findings fixed and full verification repeated after code changes.

## Scope

No detection rules, frozen benchmark labels or accuracy scorers change. Report directories remain operator-selected; this guard concerns audited source files. Native-handle sandboxing, general report-output confinement, scanner-wide filesystem races and MCP regex resource policy are separate work.
