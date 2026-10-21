# .NET credential coverage and secret-safe reports

This pass addresses the supplied .NET connection-string credential label and
adds a bounded check for literal legacy ASP.NET machine keys. The checks report
committed secret material; they do not test credentials or prove exploitation.
All supplied source, labels and scoring policy are unchanged.

## Connection-string coverage

`SECRET-DOTNET-CONN-001` recognizes literal strings in `.cs`, `.json` and
`.config` files with an endpoint, a user name and a nonempty, non-placeholder
`Password` or `Pwd` value. It supports SQL-style aliases such as `Data Source`
and `UID`, quoted values containing semicolons, ordinary JSON-compatible C#
string escapes, C# verbatim strings and named XML quote entities.

The supplied case is `dotnet-hr/Services/EmployeeRepository.cs:11`. Its credential
value is omitted from this report. The new rule detects it through the redacting
secret pipeline, rather than adding a source-code rule that could display it.

Passwordless integrated authentication and managed identity stay quiet, as do
empty values, environment/format placeholders and interpolated strings. A
literal password is still reported when authentication settings would ignore it:
the claim is that secret material is committed, not that this connection uses it.
There is no entropy threshold; short credentials can also be secrets.

Microsoft's [connection-string guidance](https://learn.microsoft.com/en-us/sql/connect/ado-net/connection-strings)
recommends identity-based authentication where available. Its
[authentication documentation](https://learn.microsoft.com/en-us/sql/connect/ado-net/sql/authentication-sql-server)
explains that integrated security ignores embedded user/password settings. Neither
fact makes a committed credential safe to publish.

## Recent attack evidence and the additional focus

This is recent exploitation of an established weakness, not a newly invented
ViewState attack:

- Microsoft reported attacks using publicly disclosed ASP.NET machine keys in
  February 2025, including an observed December 2024 incident.
  [Microsoft investigation](https://www.microsoft.com/en-us/security/blog/2025/02/06/code-injection-attacks-using-publicly-disclosed-asp-net-machine-keys/).
- Mandiant's May 25, 2026 KnowledgeDeliver report describes a late-2025 incident
  involving keys shared across customer deployments, tracked as CVE-2026-5426.
  [Mandiant investigation](https://cloud.google.com/blog/topics/threat-intelligence/knowledgedeliver-viewstate-deserialization-vulnerability/).

That evidence makes key exposure a useful static-analysis focus.
`SECRET-ASPNET-MACHINEKEY-001` recognizes exact `<machineKey>` elements and exact
`validationKey`/`decryptionKey` attributes containing literal hex material in
`.config` files. `AutoGenerate,IsolateApps`, placeholders and repeated-character
dummy values stay quiet. Quote-aware attribute parsing rejects lookalike element
names, lookalike attributes and attribute text masquerading as configuration.

The finding concerns legacy ASP.NET configuration, not ASP.NET Core's key-storage
mechanism. It does not establish that a key is public, shared across deployments,
active, or usable for a particular CVE. A fixed key may be needed across a web
farm; protect and rotate it consistently rather than blindly replacing it with
automatic per-machine keys. Microsoft's [key-format documentation](https://devblogs.microsoft.com/dotnet/cryptographic-improvements-in-asp-net-4-5-pt-1/)
describes the automatic-key options.

This pass adds generated vulnerable/safe key fixtures, not a new historical CVE
pair. The four external benchmarks therefore remain a regression check, not
independent validation of the new machine-key detector. Runtime web-shell and
process telemetry described in the investigations are outside this static scanner.

## Redaction changes and tests

The old engine truncated snippets before replacing a detected secret. It also
redacted only the secret finding's own snippet, leaving neighbouring triage context
and other findings on the same line exposed.

The engine now omits detected secret-bearing lines before truncation, for every
finding on those lines. It no longer copies raw secret values into intermediate
engine findings. Triage context uses the same redaction, including multiline
machine-key tags and PEM private-key bodies. A detected PEM header without a
recognized footer causes the remaining file to be withheld from context.

Known exact values and their JSON-escaped forms are also omitted when repeated
elsewhere in the same file. Suppression comment lines and suppression/ignore
explanations are withheld for files containing detected secrets. With more than
256 distinct redaction values, all source lines are withheld instead of attempting
unbounded matching. These choices can remove useful context; file/line locations
remain available for authorized local inspection.

Generated-marker tests cover JSON findings, SARIF, HTML, JUnit, Markdown and
triage requests; multiple secrets on one line; long snippets; adjacent non-secret
findings; trusted/untrusted suppressions; repeated passwords; and PEM bodies.
This is protection for detected secrets and recognized representations, not a
guarantee that arbitrary obfuscated or undetected credentials cannot enter reports.
An additional static check on the supplied .NET app confirmed its detected
connection credential value is absent from all six output formats; the value
was not printed or published.

## Review findings

The first review reproduced leaks through suppression metadata and adjacent PEM
body context. The second independently reproduced the suppression leak and found
XML lookalike false positives. Regressions failed before fixes were applied.
A recheck then found a repeated password in a suppression comment entering a
nearby finding's context; the regression was extended and redaction corrected.
Both reviewers independently rechecked the final changes and found no further
blocking issues in their review scope.
All 213 scanner tests and 165 vulnerable/safe regression pairs pass. The two new
corpus pairs generate connection passwords and machine keys at test time.

## Bounds and remaining gaps

- Connection-string literals are single-line, with a 4,000-character line limit
  and at most 64 parsed fields. Multiline/raw C# strings, string concatenation,
  builder APIs, ODBC brace quoting and numeric XML entities are not supported.
- The endpoint aliases are SQL-style. Provider-specific forms such as Npgsql
  `Host=...` are not yet covered. The check does not resolve custom providers.
- Machine-key scanning is limited to 1 MiB files, 8,192-character tags, 64
  attributes and even-length 32–128-character hex values. Duplicate attributes
  are declined. XML entity-encoded key material is outside this subset.
- Comments can expose secret material even when inactive; the checks do not
  equate detection with runtime use. There is no credential validation, online
  key lookup, target execution or new installed dependency.
- Existing .NET authorization, environment-context and security-sensitive
  randomness gaps remain, along with the two disputed labels documented in the
  [previous .NET pass](DOTNET-COVERAGE.md). Labels were not changed to improve scores.

## Final measurements

| Dataset | Cases | TP before → after | FP before → after | TN after | FN after |
|---|---:|---:|---:|---:|---:|
| [OWASP Java 1.2](benchmarks/owasp-java-1.2-dotnet-secrets.json) | 2,740 | 571 → 571 | 289 → 289 | 1,036 | 844 |
| [Juliet Java 1.3](benchmarks/juliet-java-1.3-dotnet-secrets.json) | 57,649 | 2,410 → 2,410 | 1,172 → 1,172 | 27,596 | 26,471 |
| [SARD 115](benchmarks/sard-115-dotnet-secrets.json) | 20 | 10 → 10 | 0 → 0 | 0 | 10 |
| [CVE historical policy](benchmarks/cve-fixes-dotnet-secrets.json) | 16 | 1 → 1 | 1 → 1 | 7 | 7 |
| [Supplied apps](benchmarks/supplied-apps-dotnet-secrets.json) | 227 | 86 → 87 | 11 → 11 | 79 | 50 |
| .NET subset of supplied apps | 21 | 8 → 9 | 0 → 0 | 7 | 5 |

The single gained detection is the connection-string credential label. .NET label
recall rises from **57.1% to 64.3%**, with no new false positives on labeled
benchmark cases and no lost true positives. Seven safe .NET labels are too few
to establish general precision. Three .NET manifest labels remain unscored
(54 overall), and unmatched supplied findings remain unclassified. The two
disputed .NET labels from the previous pass remain in the denominator.

All external case outcomes are unchanged. The historical CVE policy remains
0/8 successful parent/fix pairs. The localized policy remains 1 TP, 0 FP, 8 TN,
7 FN and 1/8 successful pairs. SARD has no negative labels, so its false-positive
rate is undefined. See the [comparison aggregate](benchmarks/dotnet-secrets-comparison.json)
and the supplied aggregate's case transitions.

All final runs use source SHA-256
`0c82433af17a5fcc07eac9efdfa41caa4b0389045fc05046e44999dc7807b29b`.
The comparator completed successfully against the PR #14 baseline.

## Reproduction

```text
npm test
npm run selftest
node bin/kayfabe.js benchmark owasp-java appsec-out/benchmarks/owasp-java --out appsec-reports/benchmarks/dotnet-secrets-owasp
node bin/kayfabe.js benchmark juliet-java appsec-out/benchmarks/juliet-java-1.3/Java --out appsec-reports/benchmarks/dotnet-secrets-juliet
node bin/kayfabe.js benchmark sard appsec-out/benchmarks/sard-115 --out appsec-reports/benchmarks/dotnet-secrets-sard
node bin/kayfabe.js benchmark cve-fixes appsec-out/cve-downloaded --out appsec-reports/benchmarks/dotnet-secrets-cve
node scripts/score-supplied-apps.js appsec-out/supplied-benchmarks-2026-10-20/benchmarks/apps appsec-reports/benchmarks/dotnet-secrets-after.json
node scripts/compare-dotnet-secrets.js
```

The comparison checks source/input/scorer hashes, unchanged policies, case
transitions, lost true positives and new false positives against PR #14. Supplied
sources and raw reports stay local; published aggregates contain no secret values.
