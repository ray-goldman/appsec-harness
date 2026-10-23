# Three C# false positives in the frozen development apps

This implements the first step of the approved improvement plan: remove three demonstrated false positives while preserving the existing detections. Later steps cover missed SQL/path/argument injection, ownership and FinSuite invariants, and native C analysis. Those steps are not implemented in this change.

## Frozen-key result

The application files, answer key, scoring policy and original baseline reports are unchanged. Both the default scanner and the optional `--dotnet-project-analysis` configuration produce the following result; their scores are kept separate in the evidence.

| C# units | Before | After |
| --- | ---: | ---: |
| True positives | 2 | 2 |
| False negatives | 8 | 8 |
| False positives | 3 | 0 |
| True negatives | 17 | 20 |
| Recall | 2/10 (20%) | 2/10 (20%) |
| False-positive rate | 3/20 (15%) | 0/20 (0%) |

These are **self-authored development apps**, inspected during tuning. They are neither blind nor independently authored. Zero observed false positives in 20 safe variants does not establish real-world precision. C# eligibility/scanning coverage is 30/30; native C coverage is 0/18. All 18 native C variants remain unsupported and excluded from accuracy denominators; they earn no true-negative credit.

The corrected cases are:

- `D05-r05`: command text comes from a fresh local dictionary containing only literal strings, after a failed lookup terminates execution.
- `D08-r71`: a uniquely registered service HTML-encodes a string, returns it in a simple string record, and a standalone view places it in ordinary HTML text.
- `D09-r63`: a uniquely registered service uses default JSON serialization on an anonymous object containing a string, then a standalone view places the result in an unquoted script expression.

The original command-injection (`D05-r32`) and raw-HTML (`D08-r22`) findings retain their fingerprints. No new or unmatched candidates appear. FinSuite still produces zero scanner candidates in either configuration. Its previously reviewed duplicate-reference race remains a manual finding, outside these accuracy totals; a quiet scan is not evidence that FinSuite is safe.

## Supported suppression profiles

The new index exists only to justify specific suppressions. It adds no cross-file taint detections and does not increase the general parser's reported coverage.

The command profile requires a fresh `Dictionary<string,string>` with literal entries, no aliases or additional uses, an immediately following `TryGetValue` guard whose failure throws, and one selected-value command assignment. Writes, references, opaque interpolation, unsupported identifier syntax, conditional/nested control flow and competing same-line sinks retain warnings.

The model profile requires a unique visible typed service registration, an exact supported interface signature, an unambiguous producer, a primary-constructor controller receiver, and a bodyless positional record with one string field. The helper form must bind to a visible static method returning the C# `string` keyword. Every visible caller of the selected view must establish the same fact. Default interface implementations, overload ambiguity, explicit implementations, inheritance, partial/duplicate owners, receiver writes, service collection aliases or overrides, dynamic dispatch and encoder/serializer shadows decline the proof.

HTML encoding qualifies only in ordinary HTML text under the existing balanced standalone-markup recognizer. JSON qualifies only for one exact unquoted `window.identifier = @Html.Raw(Model.Property);` script expression with default serialization. Attributes, quoted JavaScript, custom serialization, other raw output, layouts, partials, custom rendering hooks and unknown markup retain warnings. A static ASCII title is admitted without changing line numbering.

Project metadata must fit a small standard SDK profile with implicit usings. Only the documented basic framework/nullability/runtime properties and visible, bounded C# compile inclusions are admitted. Imports, references, packages, removals, external source outside the scanned root, conditional metadata, build overrides and unknown XML decline the new proofs. Visible `.props` or `.targets` files also disable them. This is not an MSBuild evaluator: use complete source snapshots and ordinary framework semantics; external tooling or build configuration outside the scan remains outside the guarantee.

The index declines incomplete inputs, directives, unsupported namespaces/aliases and parse errors. Its limits are 1,000 C#/Razor entries, 8 MiB of source, 100,000 code units and 20,000 tokens per C# file, and 512 indexed methods; command methods are further limited to 4,096 tokens and maps to 64 entries. Interpolation is opaque: only a simple numeric local from a visible flat `int.Parse` declaration is admitted in unrelated code; executable interpolation and interpolation in a command-proof method decline. No runtime dependency or target execution is added.

## Freeze and provenance

Baseline commit: `051f3a9dae193d62b3f92ee09fe84909be011971`.

Frozen implementation: `171b10fd387cf0c3ac9c5d0d0d831502a131bdb1`. Documentation is committed separately. Scanner byte hashes include line endings.

| Input | SHA-256 |
| --- | --- |
| Application ZIP | `10867c6145e432acb843bc7e793abc75a560a778502ebeccf441e28e3ef39772` |
| Evaluation ZIP | `8fa842ed1a78ec7141d980f9050f1f7328567ca3af514647c72bbbba2cde2db6` |
| Answer key | `cb041b6c7c951c954e1e6d589cd1a971db9719b125e79b1cbaf84b5db1e357d5` |
| Scoring policy | `b21ee3d15e602bfe88ac25cac9f8a9d81d6f131040647cec729d7396b644703e` |

The final phase was scored after the implementation commit. Before and after scanning, verification checked the original report manifest, all recorded target-file hashes and all three input archives, including FinSuite. Six earlier provisional scans were development probes informed by the known three false positives; their outputs remain local, separate from the final phase. No labels, CWE equivalences, matching regions or scoring thresholds were tuned.

Final candidates reuse the original adjudications only after exact fingerprint, CWE and declared operation-range checks. A previously unseen candidate stops scoring for manual adjudication. Missing former false-positive candidates become true negatives under the existing policy. Manual hunting earns no detection credit. Full source, keys, raw findings, execution commands and review probes remain local; the repository contains invented regression pairs and aggregate comparisons.

The [frozen-key comparison artifact](benchmarks/frozen-dotnet-precision-comparison.json) records each case transition, separate language/family/primary-CWE totals, coverage and provenance hashes. A second reviewer independently checked the scoring and original/current source traces, then rehashed the key, policy, adjudications and all 89 original report-manifest entries.

## Verification and both review passes

All **391 scanner tests pass**. All **189 vulnerable/fixed corpus pairs** retain 100% regression precision and recall. The three new pairs are self-authored regression coverage and are excluded from the frozen-key and existing benchmark totals.

Two fresh review contexts challenged the implementation before the PR. Pass 1 found hidden writes in interpolation/escaped identifiers, explicit interface dispatch, project source replacement and encoder-property shadowing. Pass 2 found service collection writes, helper receiver shadowing, default-interface overload dispatch, partial-controller writes, tuple assignment and explicit-import bypass of project closure. Each confirmed issue was fixed and covered by regressions.

The second reviewer rechecked the frozen commit and reran both probe suites: all 14 unsafe or unknown variants retained warnings; four positive controls still qualified for suppression. These are bounded source reviews, not proof of arbitrary C# semantics. Review also identified scaling work to consider: a dedicated type-count cap and sharing the index between proof consumers. Current byte/token/method limits remain in force.

## Remaining detection gaps

Eight C# vulnerabilities remain missed: two SQL construction cases, asynchronous path reads and writes, argument injection, two object-ownership cases, and quoted JavaScript output. Razor expressions inside quoted JavaScript or attributes can still disappear under generic C# string masking. A lack of warning there must not be described as a proven sanitizer result. General parser structural completeness still does not establish syntax or semantic coverage.

The next PR should start with syntax/DI/source/call handling for the missed injection/path operations and preserve this phase's two detections and zero observed false positives. Ownership and FinSuite's database invariant need separate evidence and acceptance gates. Native C requires an explicitly supported analysis path before any native accuracy score is reported.

## Seven existing benchmark suites

All seven suites were freshly measured for the baseline and frozen implementation. There are **zero unit transitions** in either direction: no lost true positives, new false positives, corrected false positives or recovered misses. The improvement above is confined to the new frozen development apps.

| Dataset | Units | TP before → after | FP before → after |
| --- | ---: | ---: | ---: |
| Juliet C# 1.3 | 59,282 | 1,036 → 1,036 | 470 → 470 |
| OWASP Java 1.2 | 2,740 | 571 → 571 | 289 → 289 |
| Juliet Java 1.3 | 57,649 | 2,410 → 2,410 | 1,172 → 1,172 |
| SARD PHP suite 115 | 20 | 10 → 10 | 0 → 0 |
| CVE snapshots, original policy | 16 | 1 → 1 | 1 → 1 |
| Supplied labeled apps | 227 | 87 → 87 | 11 → 11 |
| Additional self-authored .NET apps | 230 | 32 → 32 | 1 → 1 |

The [existing-suite comparison](benchmarks/frozen-dotnet-existing-benchmarks.json) verifies unchanged input hashes, labels, evaluator identities, options and policies; it checks each scoring unit and rejects mixed scanner hashes. Previously seen third-party suites, upstream fix snapshots and generated application labels remain separate evidence tiers. SARD has no safe denominator, so its FPR is unmeasured. Unmatched findings remain unclassified.

Original CVE pair success stays 0/8; the separately scored localized policy stays 1/8. Full-suite C# recall remains 3.49%, with 1.59% FPR. The older .NET application set's one Razor false positive remains outside the new supported standalone-view profile.

C# scanner duration was 120.689s → 127.220s (1.054×), within the existing 1.5× budget. These single runs shared a machine with other benchmark jobs; preparation/hashing is additional and this is not a robust performance estimate.

Measured scanner byte hashes:

- Baseline: `f0368e1aa90686f99951633564c801b4dec328bdf0a7f06b249ab84400981a9a`.
- Frozen implementation: `180a3e2bc12368ac06aea8f8aaa1c983d679eb44dd08de1994dd6f99d42ecd8c`.

Both scanner trees were checked against the declared Git commits with only CRLF/LF normalization (79 baseline files; 82 implementation files). The exact target-file inventories also match the original protocol.

For reproduction, use the seven commands in the [existing measurement protocol](PYTHON-VALUE-PRECISION.md#reproduction), then run:

```sh
node scripts/compare-dotnet-accuracy.js BEFORE AFTER comparison.json 051f3a9dae193d62b3f92ee09fe84909be011971 171b10fd387cf0c3ac9c5d0d0d831502a131bdb1
```

Use the additional .NET set with the eight labeled applications (`mvc-shop`, `minimal-api`, etc.), not the separate nine unlabeled user apps. An initial root-selection mistake yielded zero labels and was rejected before comparison; both engines were rerun against the correct unchanged 230-label input. The correction and original probe commands remain in local execution evidence.
