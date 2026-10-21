# Review of the supplied .NET detection proposal

The archive contains useful additions, but importing both commits would replace
newer work from PRs #14 and #15. This pass implements six narrowly scoped checks
and evaluates them with the existing scorer. It preserves the current secret
redaction and C# detection rules.

## Provenance and evaluation

- Input: `kayfabe-dotnet-detection.zip`, SHA-256
  `389c0a4433748bfd9078c9c06f75ebd645351a45ef82af5834815a15abec51ee`.
- Proposal tip: `854097a84c944d7deb22991797ba7c1142928890`.
- Proposal base: `12ea56f8c7c9ddba5caba4b663521e2f2fef8c3b` (PR #13).
- Comparison baseline: `3e0b67fe21d606e9b11f014eb6d660b6cffa0848` (PR #15).

The bundle and patches were read as review material. Their instructions and
performance claims were not adopted. The new sample apps were only scanned;
their builds, dependency restores, package scripts and application code were not
executed. The archive's benchmark scorer was not executed either.

The proposal's eight apps use 230 source-line labels: 139 vulnerable and 91 safe.
The existing `score-supplied-apps.js` scores the same files, labels and matching
policy before and after this change. The apps' 23 dependency labels remain
unscored because the existing adapter does not establish package/CVE identity.
Unmatched findings remain unclassified. Sources and raw scan reports stay local;
the published comparison contains label metadata and counts, not source code or
credential values.

These apps were written alongside the proposed rules. Directory names beginning
with `heldout-` do not establish independent evaluation. We make no held-out
accuracy claim, and the proposal's reported 75.5% recall is not a result of this
implementation. Labels were preserved, including unresolved and missed cases.

## Implemented

| Check | Evidence required |
|---|---|
| `NETCFG-DEBUG-001` | ASP.NET debug compilation, or tracing explicitly enabled with `localOnly=false` |
| `NETCFG-ERR-001` | Detailed ASP.NET/IIS errors or WCF exception details explicitly enabled in their configuration sections |
| `NETCFG-COOKIE-001` | `httpCookies` explicitly disables HttpOnly or the SSL requirement |
| `NETCFG-FORMS-001` | Forms authentication explicitly active with SSL disabled or URL tickets permitted; URL-based session settings are checked separately |
| `NETCFG-WCF-001` | A supported WCF binding explicitly sets its security mode to `None` |
| `CS-TLS-002` | A simple `ServicePointManager.SecurityProtocol` assignment selects SSL 3.0, TLS 1.0 or TLS 1.1 |

XML checks require exact element and attribute names and the expected ancestor
path in `Web.config` or `App.config`. They handle multiline tags, either quote
style, comments and an initial UTF-8 BOM. Lookalike attributes, invalid syntax,
namespaces and transforms do not produce findings from these checks.

The WCF rule does not treat `clientCredentialType="None"` as unencrypted
transport. Microsoft documents an [anonymous-client HTTPS configuration](https://learn.microsoft.com/en-us/dotnet/framework/wcf/feature-details/transport-security-with-an-anonymous-client)
that provides confidentiality and integrity. Similarly, the TLS rule leaves OS
defaults and modern protocol selections quiet, consistent with
[Microsoft's TLS guidance](https://learn.microsoft.com/en-us/dotnet/framework/network-programming/tls).

These are configuration candidates, not assertions about effective deployment.
The messages ask reviewers to check transforms, inheritance, endpoint use and
external protection. They do not require new runtime dependencies or network
access.

## Suggestions deferred or rejected

| Proposal | Reason |
|---|---|
| Replace the C# rules and taint implementation | The proposal predates the current rules. Its generic neutralizer list treats HTML encoding, path basename extraction and arbitrary `Sanitize*` names as safe across unrelated sinks. Guard names nearby do not prove validation of the actual value on every path. |
| Suppress `Html.Raw(HtmlEncode(...))` findings | A trial correction failed review: earlier dynamic markup can put a later expression in a JavaScript context. The existing false positive remains until Razor context and symbol binding can be established. |
| New connection-string, machine-key and generic-secret pattern rules | PR #15 already provides connection-string and machine-key detection through the redaction path. Additional credential pattern rules need matching redaction coverage before adoption. |
| Blanket JWT warnings | The proposal conflates signing-key validation, lifetime policy and signature verification. Existing unsigned-token detection and its precision tests remain unchanged. |
| Name-based IDOR, admin-route and mass-assignment rules | Names and absent local checks do not establish authorization behavior, global policies or which properties can actually be written. |
| Blanket CORS, cookie, antiforgery and WCF warnings | Public APIs, non-sensitive cookies, token-authenticated endpoints and anonymous HTTPS can be intentional. These require context that the proposed checks do not establish. |
| NuGet parsing and curated advisories | The proposal explicitly says its affected ranges were written from memory and need verification. Its dependency scorer matches findings by directory and package/version text, not exact advisory identity. A separate verified NuGet adapter is needed. |
| Treat every Razor/WebForms extension as C# | Markup, directives and embedded languages require context-aware parsing before broad taint or safety claims. |

For example, [`ValidateIssuerSigningKey`](https://learn.microsoft.com/en-us/dotnet/api/microsoft.identitymodel.tokens.tokenvalidationparameters.validateissuersigningkey?view=msal-web-dotnet-latest)
controls validation of the signing key and defaults to false; it is not the
unsigned-token switch. ASP.NET tracing also defaults to
[`LocalOnly=true`](https://learn.microsoft.com/en-us/dotnet/api/system.web.configuration.tracesection.localonly?view=netframework-4.8.1),
so `enabled=true` alone does not prove remote trace-viewer exposure.

The next useful expansion is explicit framework-bound parameter sources with
method-local bindings and sink-specific sanitizers. NuGet support should follow
with verified advisory ranges, precise manifest provenance and negative cases
for comments, central version properties, conditions and lockfile overrides.

## Review and verification

Both independent code-review passes found issues that were addressed:

1. Reject malformed XML comments, declarations, control characters and
   unsupported text before emitting configuration findings.
2. Exclude C# declarations that shadow either `ServicePointManager` or
   `SecurityProtocolType`.
3. Accept valid BOM-prefixed XML declarations.
4. Remove the experimental Razor suppression after the dynamic-context
   counterexample; its regression remains.
5. Require forms authentication to be explicitly active before reporting its
   forms-ticket settings; Windows authentication is a negative case.

Both reviewers rechecked the fixes. The final test run passes **219 tests** and
**171 vulnerable/fixed regression pairs**. Existing redaction tests across all
six report formats are included.

All final benchmark runs and the comparison pass:

| Dataset | TP before → after | FP before → after | Final TN | Final FN |
|---|---:|---:|---:|---:|
| OWASP Java 1.2 | 571 → 571 | 289 → 289 | 1,036 | 844 |
| Juliet Java 1.3 | 2,410 → 2,410 | 1,172 → 1,172 | 27,596 | 26,471 |
| NIST SARD 115 | 10 → 10 | 0 → 0 | 0 | 10 |
| CVE-fix historical policy | 1 → 1 | 1 → 1 | 7 | 7 |
| Original supplied apps | 87 → 87 | 11 → 11 | 79 | 50 |
| New proposal apps | 23 → 32 | 1 → 1 | 90 | 107 |

The new apps gain **nine detections**, increasing labeled recall from **16.5%
to 23.0%**. Their labeled FPR remains **1/91 (1.1%)**. No true-positive label
was lost and no safe label acquired a finding in any dataset. The original
supplied .NET subset remains **9/14 vulnerable labels detected, 0/7 safe labels
flagged**. This change does not reduce the remaining 11 original supplied FPs.

SARD has no negative labels, so its FPR is undefined. Historical CVE pairs remain
0/8 successful; the separate localized policy remains 1 TP, 0 FP, 8 TN, 7 FN and
1/8 successful pairs. All external case outcomes are unchanged.

See the [external comparison](benchmarks/dotnet-proposal-comparison.json),
[original supplied comparison](benchmarks/supplied-apps-dotnet-proposal.json) and
[new-app comparison](benchmarks/claude-dotnet-apps-comparison.json). Final source
SHA-256: `08eaa10d4fc7ebe403f514b7d5f87e0cd36158c3b02a869f72ccc8a80e5111d0`.

The baseline hash check caught a checkout line-ending difference. The new apps'
baseline uses `3f64530eeebf7085f0e4bc967ebdac79528933579d7d9ac4c1a5b25cafae69ee`;
the retained pre-merge PR #15 reports use
`0c82433af17a5fcc07eac9efdfa41caa4b0389045fc05046e44999dc7807b29b`.
The verification script compares every baseline source file against the pinned
Git blob after LF normalization, reconstructs the original baseline byte hash,
then reruns the new apps with the identical scorer. Counts, per-case outcomes,
input hashes and policy all match the initial baseline. The aggregate records
this verification rather than silently accepting mismatched hashes.

## Bounds and remaining gaps

The XML reader is a bounded subset, not a validating XML parser or a .NET
configuration evaluator. It accepts at most 1 MiB, 10,000 elements, 64 levels,
8 KiB per tag and 64 attributes per element. DTDs, entities, text-bearing
sections, namespaces, deployment transforms, external config and `<location>`
settings are not interpreted. It does not infer defaults, active named bindings,
deployment environment or all possible configuration-schema errors.

TLS detection uses the existing bounded C# context checks, requires an explicit
`using System.Net`, and handles only direct enum assignments. It does not resolve
project-wide symbols, evaluate branches or follow configuration overrides. Its
medium-confidence result requires triage.

The one labeled Razor false positive in the new apps remains. Broad controller
and Minimal API flows, cross-file helpers, dependency CVEs and authorization
logic remain substantial gaps. Adding six rules does not establish that .NET
coverage is generally strong.

## Reproduce

Extract only `benchmarks/apps/dotnet` from the supplied bundle's tip into the
ignored `appsec-out/claude-dotnet-review` directory. Do not execute the apps.
Capture `before.json` with PR #15 and the unchanged source-line scorer, then run:

```text
npm test
npm run selftest
node scripts/score-supplied-apps.js appsec-out/claude-dotnet-review/benchmarks/apps/dotnet appsec-out/claude-dotnet-review/after.json
node scripts/score-supplied-apps.js appsec-out/supplied-benchmarks-2026-10-20/benchmarks/apps appsec-reports/benchmarks/dotnet-proposal-after.json
node bin/kayfabe.js benchmark owasp-java appsec-out/benchmarks/owasp-java --out appsec-reports/benchmarks/dotnet-proposal-final-owasp
node bin/kayfabe.js benchmark juliet-java appsec-out/benchmarks/juliet-java-1.3/Java --out appsec-reports/benchmarks/dotnet-proposal-final-juliet
node bin/kayfabe.js benchmark sard appsec-out/benchmarks/sard-115 --out appsec-reports/benchmarks/dotnet-proposal-final-sard
node bin/kayfabe.js benchmark cve-fixes appsec-out/cve-downloaded --out appsec-reports/benchmarks/dotnet-proposal-final-cve
git worktree add --detach appsec-out/claude-dotnet-review/baseline-check 3e0b67fe21d606e9b11f014eb6d660b6cffa0848
node scripts/verify-dotnet-proposal-baseline.js
node scripts/compare-dotnet-proposal.js
```

The comparator needs the retained PR #15 reports. It checks source, input and
scorer hashes, labels, scoring policy, lost true positives and new false
positives. No benchmark label was changed for this implementation.
