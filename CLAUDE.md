@AGENTS.md

## Claude Code specifics

- The `/appsec-review` skill (`.claude/skills/appsec-review/`) runs the full audit → triage → report loop.
- `.mcp.json` registers the `appsec` MCP server for this project (`node bin/kayfabe.js mcp`). Approve it when prompted, or use the CLI — both are equivalent.
- `.claude/settings.json` pre-allows the harness CLI and denies package installs/builds so a scanned project's scripts can never be triggered from this workspace.
- For large audits, triage one OWASP category at a time and save progress with `appsec_save_triage` (`merge: true`) or by appending to `triage.json`; run `triage validate` after each batch.
