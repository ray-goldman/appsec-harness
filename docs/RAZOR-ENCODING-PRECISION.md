# Razor encoding: standalone text and the remaining context gap

This pass refines `CS-XSS-001` for a bounded standalone Razor profile:

```cshtml
@model CatalogItem
<div class="description">@Html.Raw(System.Net.WebUtility.HtmlEncode(Model.Description))</div>
```

The fully qualified framework encoder protects ordinary HTML text. It does not establish JavaScript safety; output encoding must match the output context. [Microsoft's ASP.NET Core XSS guidance](https://learn.microsoft.com/en-us/aspnet/core/security/cross-site-scripting?view=aspnetcore-10.0) distinguishes those contexts and warns about unencoded `HtmlString` output.

## Supported profile

The view may contain static text, admitted ordinary HTML elements with balanced nesting, static quoted or boolean attributes, strict HTML comments, literal model/namespace directives, and the exact encoded-output shape above. Encoder input must be a simple identifier or member path. Every matching raw-output sink on a reported line must qualify before that line is refined.

Unknown Razor expressions, ordinary model output with an unresolved runtime type, unencoded raw output, code blocks, custom encoders, concatenation and unsupported directives retain warnings. Model properties can be `IHtmlContent`; their output cannot be assumed to preserve the following browser context without type evidence.

The entire view declines the proof when it contains script, style, textarea, title or other raw-text elements; foreign content, templates, custom elements and unsupported/malformed markup also decline it. Attribute contexts never qualify. This recognizer does not implement the HTML tokenizer's script escaped/double-escaped states. Those states are defined in the [HTML parsing standard](https://html.spec.whatwg.org/multipage/parsing.html#script-data-double-escaped-state), and their complexity motivated rejecting raw-text elements entirely.

Visible layout/ViewStart files, layout/body/section/partial rendering markers, recognized C# custom-rendering hooks, custom Razor bases/injection/tag helpers, aliases, custom helper references/registrations and visible framework-name shadows disable the project proof. It assumes ordinary ASP.NET Core standalone view rendering and framework semantics; it does not establish arbitrary runtime or external rendering behavior.

The source index must be complete within the configured scan scope. Limits are 1,000 C#/Razor entries, 8 MiB total source, 100,000 code units per file, 20,000 tokens per C# identity check, 256 Razor atoms per view, 4,096 code units per admitted expression tail, 64 element nesting levels and 15 tokens per encoded member path. Incomplete, unreadable, binary, oversized or unsupported input retains warnings. No target code is executed and no runtime dependency is added.

## Why the original app warning remains

An early implementation removed the app set's one labeled false positive. Review showed that this was an unsafe result: earlier raw output can change the browser context of a later expression, and a layout can insert a view into JavaScript. HTML encoding alone does not prove safety after either transition.

For example, this is not eligible for suppression:

```cshtml
@Html.Raw(Model.OpenMarkup)
@Html.Raw(System.Net.WebUtility.HtmlEncode(Model.Description))
```

The first value could open a script element. Similarly, a layout can place `RenderBody()` inside a script element. The existing supplied view has preceding unencoded output, other unresolved output and script content. Its encoded-text label is therefore retained under this conservative profile. Labels, source and scorer policy were not changed to manufacture a lower FP count; the zero-FP app gate remains unmet.

The next step for that case is typed Razor expression analysis plus caller/layout/partial context summaries. A line-local search for an encoder cannot establish those facts. Current C# string masking also misses some Razor expressions embedded in quoted JavaScript or attributes; this pass does not claim to fix their detection.

## Regression evidence and reviews

All **353 tests pass** and all **186 vulnerable/fixed corpus pairs** retain 100% regression precision and recall. These are self-authored expectations, not independent detection accuracy.

The [paired regression comparison](benchmarks/razor-encoding-regression-comparison.json) records identical input bytes for both engines. The standalone encoded HTML-text sibling loses one false-positive candidate, while its unencoded sibling retains its candidate. The script-context case retains its warning; its JSON-serialized sibling remains quiet. These cases are excluded from standard benchmark totals.

Both source review passes completed after fixes:

- Pass 1 found context changes from earlier raw/helper output and layouts, plus incorrect handling of malformed closing tags, unquoted attributes and abrupt HTML comment endings. These now decline the proof.
- Both reviewers reproduced a script double-escape case that a partial tokenizer misread. The final implementation rejects all raw-text elements.
- The final identity audit and pass 2 found helper replacement paths, including explicit interface implementations. All visible C# `Raw` identifiers and recognized helper types/registrations now disable the proof.
- Further tests cover same-line mixed sinks, framework-name shadows, incomplete input, resource limits and line counting across boolean attributes.

Local development-app rescans retain identical candidate fingerprint sets, including previously reviewed SQL findings. Supplied application source, labels, findings and comparison artifacts remain local. No app-level recall estimate or independent holdout claim is made.

## Measurement protocol

The baseline is merged main `704369c2dd34aeaa62b03179eac7abf1f5cac184`, freshly measured from a separate Git archive. The frozen implementation is `e597f5d39d3408c4218e9188ad6fcdab90261fea`. Documentation is committed separately.

Scanner byte hashes include line endings. Input hashes, labels, options, scoring policy, evaluator identities and per-unit labels must match before comparison. Scanner files were checked against their declared Git commits with text line endings normalized; evaluator source is unchanged.

Dataset tiers remain separate: previously seen third-party synthetic suites, upstream CVE snapshots under original/localized policies, and self-authored labeled apps. SARD has no safe denominator; its FPR is unmeasured. Unmatched findings remain unclassified. This development pass does not consume an independent holdout.

Reproduce the seven suites with the commands in the [MVC SQL measurement guide](DOTNET-MVC-SQL.md#measurement-protocol), then compare the two commits above using `scripts/compare-dotnet-accuracy.js`.

## Seven existing benchmark results

All seven suites have **zero unit transitions**: no lost true positives, new false positives, corrected false positives or recovered misses under their existing scoring policies. This pass does not improve these seven benchmark scores.

The [comparison artifact](benchmarks/razor-encoding-benchmark-comparison.json) checks matching input hashes, scoring identities and unit labels, records canonical raw-report hashes, and rejects mixed engine hashes.

| Dataset | Units | TP before -> after | FP before -> after |
|---|---:|---:|---:|
| Juliet C# 1.3 | 59,282 | 1,036 -> 1,036 | 470 -> 470 |
| OWASP Java 1.2 | 2,740 | 571 -> 571 | 289 -> 289 |
| Juliet Java 1.3 | 57,649 | 2,410 -> 2,410 | 1,172 -> 1,172 |
| SARD PHP suite 115 | 20 | 10 -> 10 | 0 -> 0 |
| CVE snapshots, original policy | 16 | 1 -> 1 | 1 -> 1 |
| Supplied labeled apps | 227 | 87 -> 87 | 11 -> 11 |
| Additional self-authored .NET apps | 230 | 32 -> 32 | 1 -> 1 |

The localized CVE policy is checked separately in the artifact. Original pair success is **0/8**; localized pair success is **1/8**.

Full-suite C# recall remains 3.49%, with 1.59% FPR. The existing Razor false positive and broader detection gaps remain. New regression fixtures are excluded from these totals.

C# scanner duration was 93.055s -> 93.289s (1.003x), within the existing 1.5x budget. Fresh single runs on a shared machine do not establish robust performance estimates; preparation/hashing time is additional.

Measured scanner byte hashes:

- Baseline: `09a0b15a493442fe6d76036e92d3d70467743be11b2c08287228e511d333b565`.
- Frozen implementation: `e3018f76db053604fb80de1f3b3919fedbc94b7b5a835b7d549def1b4be57f73`.
