# .NET coverage: reviewed labels and bounded detection

## Dataset independence and status

Evaluation tiers are defined in the [dataset policy](benchmarks/dotnet-evaluation-policy.md)
and tracked in the [dataset registry](benchmarks/dotnet-datasets.json). Own .NET
apps, including prior `HELD-OUT.sha256` entries, are **self-authored regression**
data; their earlier held-out numbers are not blind or independent. Juliet C# 1.3
is **third-party real code, seen**. The held half is retired as a holdout because
it informed the CWE-329 scoping fix. dotnet/eShop and OWASP/WebGoat.NET are also
seen third-party data and are excluded from the public-repository sample.

No independently authored ASP.NET set or adjudicated public-repository sample
is currently available, so those gates are **not measured**. Do not treat the
existing app results as satisfying either gate. The older tables below preserve
historical counts and must be read with these tier labels.

This pass reviews all 11 previously missed labels in the supplied `dotnet-hr`
app. It adds five narrow detections and five vulnerable/safe regression pairs.
The supplied files, labels and scoring policy are unchanged. A benchmark label
is not an independently established vulnerability: two labels conflict with
the declared framework behavior, and several need deployment context.

## Review of the 11 missed labels

Locations below are relative to the supplied `dotnet-hr` directory. Target code
was read and scanned as data; no target build, application or tests were run.
The project declares `net6.0` in `HrPortal.csproj`.

| Label and location | Static assessment | Disposition |
|---|---|---|
| Missing authorization, `Controllers/EmployeesController.cs:30` | Salary data is returned without a visible action/class authorization attribute. Global policies, filters and upstream protection must also be checked. | Remains missed; adding a finding for every missing attribute would flag public or globally protected endpoints. |
| Path traversal, `Controllers/EmployeesController.cs:45` | A bound query string is passed directly to `Path.Combine` and `PhysicalFile`; no local containment guard appears. | New `CS-PATH-001`. The guarded method at line 54 remains unflagged. |
| Default XmlDocument XXE, `Controllers/EmployeesController.cs:70` | The label assumes an unsafe default resolver. That assumption does not hold for the declared modern .NET target; no external resolver is assigned here. | Disputed label, retained unchanged as a benchmark FN. No rule added to manufacture a detection. |
| Shell command, `Controllers/EmployeesController.cs:87` | Query input is inserted inside the quoted command supplied to `sh -c`. The old rule missed the escaped quotes. | New `CS-CMDI-002`; the legacy command rule is unchanged. |
| Open redirect, `Controllers/EmployeesController.cs:95` | An explicitly bound query parameter is returned directly through `Redirect`. | New `CS-REDIRECT-001`; `LocalRedirect` and guarded examples remain unflagged. |
| Embedded connection credential, `Services/EmployeeRepository.cs:11` | A connection string embeds authentication material. Its value is intentionally omitted here. | Remains missed. Extend the redacting secret pipeline separately; a normal code finding must not expose credential text. |
| MD5, `Services/EmployeeRepository.cs:35` | MD5 hashes a password-named string parameter. Intended security use is inferred from the parameter/context, not proven by a call graph. | New medium-confidence `CS-CRYPTO-001`; PBKDF2 and non-password checksum examples remain unflagged. |
| Random OTP, `Services/EmployeeRepository.cs:47` | `System.Random` generates a six-digit value in an OTP-named method. It is unsuitable for security tokens, but no consumer establishes its security use. | Remains missed. Model the security-sensitive use before flagging all ordinary randomness. |
| JWT validation disabled, `Startup.cs:15` | The initializer explicitly sets `RequireSignedTokens = false` along with other disabled checks. Runtime use and later configuration still require triage. | New `CS-JWT-001`; do not confuse `ValidateIssuerSigningKey = false` alone with disabled signature validation. |
| Wildcard CORS with credentials, `Startup.cs:27` | ASP.NET Core rejects this combination; it does not establish an exploitable credentialed wildcard policy. The shown startup also lacks CORS middleware activation. | Disputed label, retained as a benchmark FN. A configuration failure is different from demonstrated CWE-942 exposure. |
| Developer exception page, `Startup.cs:34` | The call has no local environment guard. Exposure depends on startup selection, environment and reachable errors. | Remains missed. A later check needs environment/branch context and safe development-only counterexamples. |

Microsoft documents the [modern XmlDocument resolver default in its analyzer](https://source.dot.net/Microsoft.CodeAnalysis.NetAnalyzers/Microsoft.NetFramework.Analyzers/DoNotUseInsecureDtdProcessing.cs.html),
the [invalid CORS combination](https://learn.microsoft.com/en-us/aspnet/core/security/cors?view=aspnetcore-6.0),
[global authorization policies](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/policies),
and [RequireSignedTokens](https://learn.microsoft.com/en-us/dotnet/api/microsoft.identitymodel.tokens.tokenvalidationparameters.requiresignedtokens?view=msal-web-dotnet-latest).
The label review uses those framework semantics without executing the sample.

## Supported shapes and limits

These are bounded source checks, not Roslyn analysis or a general C# taint engine.
They add candidates and never suppress findings from existing rules. No compiler,
target dependency or runtime package is installed.

- Path and redirect checks require an ordinary public, nonstatic `IActionResult`
  method inside a class directly inheriting `ControllerBase`, an MVC import and
  an explicitly attributed string parameter (`FromQuery`, `FromRoute`, `FromForm`
  or `FromHeader`). The body must consist of the supported single return.
- Shell detection uses the same action ownership. It requires the diagnostics
  import, `Process.Start` with `/bin/sh` or `bash`, a literal prefix that opens
  the quoted `-c` command, the bound parameter, a closing quote, and `return Ok()`.
  Optional assignment of the process to a `var` is supported. Positional shell
  arguments after a closed constant command are outside this check.
- MD5 detection recognizes the direct `BitConverter.ToString` / `MD5.Create` /
  `ComputeHash` / `Encoding.UTF8.GetBytes` chain in a single-return method whose
  input is named `pw`, `password` or `passwd`. This naming heuristic can still
  require human triage; it is not general cryptographic-use analysis.
- JWT detection recognizes a simple `TokenValidationParameters` initializer
  assigned through an options member, containing only supported boolean members.
  Custom validators or other properties are outside this subset. An immediate
  unconditional same-object `RequireSignedTokens = true` correction prevents
  this finding. Intervening uses, branches and nonlocal configuration are not
  resolved; a finding remains a candidate for review.
- Nonactions, static actions, unrelated/nested classes and recognized local type
  and method shadows are excluded. Cross-file types, global filters, custom binders,
  inherited controllers and helper flows are not resolved.
- Checks skip files over 100,000 characters, non-ASCII/NUL input, preprocessor
  directives, raw/verbatim string syntax and using aliases. Method signatures
  and bodies are bounded at 1,000 and 4,000 characters; class headers at 500,
  brace depth at 64 and JWT initializers at 2,000. Unsupported syntax is a
  coverage limit, never evidence that code is safe.

## Review passes

Both independent reviewers reproduced false positives involving a controller
elsewhere in the file, `[NonAction]` helpers and an immediate secure JWT override.
Regressions reproduced those failures before fixing ownership, action eligibility
and the supported override. Static-method and nested-class negatives were added.

The second reviewer also caught constant concatenation in the proposed extension
to the legacy command regex. That change was removed. The replacement check uses
an explicitly bound parameter in a supported controller action. Both rechecks
then found shell positional-argument and custom `Process` false positives. New
regressions reproduced them before narrowing the command argument and API checks.
Both reviewers independently rechecked the final fixes and reported no further
actionable findings within the supported subset. All 203 scanner tests and 163
paired regression cases pass; the regression count includes five new C# pairs.

## Final measurements

| Dataset | Cases | TP before → after | FP before → after | TN after | FN after |
|---|---:|---:|---:|---:|---:|
| [OWASP Java 1.2](benchmarks/owasp-java-1.2-dotnet.json) | 2,740 | 571 → 571 | 289 → 289 | 1,036 | 844 |
| [Juliet Java 1.3](benchmarks/juliet-java-1.3-dotnet.json) | 57,649 | 2,410 → 2,410 | 1,172 → 1,172 | 27,596 | 26,471 |
| [SARD 115](benchmarks/sard-115-dotnet.json) | 20 | 10 → 10 | 0 → 0 | 0 | 10 |
| [CVE historical policy](benchmarks/cve-fixes-dotnet.json) | 16 | 1 → 1 | 1 → 1 | 7 | 7 |
| [Supplied apps](benchmarks/supplied-apps-dotnet.json) | 227 | 81 → 86 | 11 → 11 | 79 | 51 |
| .NET subset of supplied apps | 21 | 3 → 8 | 0 → 0 | 7 | 6 |

The .NET label recall rises from **21.4% to 57.1%**. No new false positives or
lost true positives were observed in these datasets. Only seven safe .NET labels
are scored, so this is not evidence of general zero-FP performance. Three .NET
manifest labels remain unscored (54 across all supplied apps); unmatched findings
remain unclassified. The original disputed labels stay in the denominator.

The historical CVE pair score remains 0/8. The localized policy remains 1 TP,
0 FP, 8 TN, 7 FN and 1/8 successful pairs. SARD has no negative labels, so its
false-positive rate is undefined. External case transitions are recorded in the
[comparison aggregate](benchmarks/dotnet-comparison.json); the supplied aggregate
records its five `fn→tp` transitions and unchanged cases.

All final runs use source SHA-256
`5c4055c7f17d6425004ad5044962d7aa13a06a32bb78be2aa121ac101619fc58`.
The comparator completed successfully against the PR #13 baseline.

## Reproduction

```text
npm test
npm run selftest
node bin/kayfabe.js benchmark owasp-java appsec-out/benchmarks/owasp-java --out appsec-reports/benchmarks/dotnet-owasp
node bin/kayfabe.js benchmark juliet-java appsec-out/benchmarks/juliet-java-1.3/Java --out appsec-reports/benchmarks/dotnet-juliet
node bin/kayfabe.js benchmark sard appsec-out/benchmarks/sard-115 --out appsec-reports/benchmarks/dotnet-sard
node bin/kayfabe.js benchmark cve-fixes appsec-out/cve-downloaded --out appsec-reports/benchmarks/dotnet-cve
node scripts/score-supplied-apps.js appsec-out/supplied-benchmarks-2026-10-20/benchmarks/apps appsec-reports/benchmarks/dotnet-after.json
node scripts/compare-dotnet.js
```

The comparator uses PR #13's full local reports and committed aggregates. It
checks source/input/scorer hashes, unchanged labels and policies, case transitions,
lost true positives and new false positives. Raw reports and supplied sources
stay local. Aggregate reports include locations and labels, not credential values.
