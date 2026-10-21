# Independent ASP.NET Application Authoring Brief

## Access and independence rules

This brief is the only Kayfabe material the author may receive. Work in a clean checkout that contains this brief and no Kayfabe source, rules, labels, existing benchmark applications, or scorer. Do not search for Kayfabe, its rules, or prior benchmark material while authoring. Record the author/system identifier, date, exact materials visible, and an isolation declaration. If a language model is used, record its model identifier and training cutoff; the custodian must verify the repository's first-public date and confirm the cutoff predates it. If any condition fails, classify the data as self-authored regression, not independent.

The author prepares six to eight small ASP.NET applications from the feature briefs below. Use ordinary framework conventions and keep each app self-contained. For every vulnerable example, include a safe twin that exercises a similar feature with a safe outcome. Do not use comments to identify vulnerabilities or encode the labels in names.

## Application feature briefs and fixed CWE coverage

1. **Order history and customer support.** Users browse orders, update delivery preferences, and leave support notes. Include CWE-639, CWE-89, and CWE-79.
2. **Document and image library.** Users view and organize uploaded materials and request previews. Include CWE-22, CWE-79, and CWE-918.
3. **Account access and invitations.** Users sign in, manage profiles, accept invitations, and continue to a requested page. Include CWE-352, CWE-601, and CWE-639.
4. **Operations dashboard.** Staff view and update records through a small administrative interface. Include CWE-862, CWE-89, and CWE-79.
5. **Report generation service.** Users submit parameters to create and download reports. Include CWE-78, CWE-22, and CWE-89.
6. **Integration settings portal.** Users configure outbound integrations and inspect delivery status. Include CWE-918, CWE-79, and CWE-352.
7. **Optional additional app.** A catalog or inventory tool with search, filters, saved views, and detail pages. Include CWE-89, CWE-639, and CWE-79.
8. **Optional additional app.** A team workspace with member management, comments, and export features. Include CWE-862, CWE-352, and CWE-22.

The CWE list is fixed before authoring. Include at least one vulnerable and one safe labeled region for each CWE across the complete set. Keep application features plausible; do not force an issue into a feature where it does not fit.

## Labels

For every vulnerable and safe region, provide:

- Relative file path and inclusive start/end line numbers.
- CWE identifier.
- Polarity: `vulnerable` or `safe`.
- One-sentence rationale describing the behavior.
- For a flow crossing methods or files, source file/line and sink file/line.

Use distinct safe and vulnerable code regions. Labels must identify the sink region for vulnerable flows and the relevant safe construct for safe twins. Do not include scanner findings, expected rule IDs, or any material derived from Kayfabe.

## Freeze package

Return source files, labels, a SHA-256 manifest covering both, and the authoring/isolation record to the custodian. The custodian keeps the package sealed until the scheduled phase score. Do not share app source or labels with rule authors before that score.
