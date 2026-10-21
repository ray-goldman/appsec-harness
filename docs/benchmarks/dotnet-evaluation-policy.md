# .NET Evaluation Policy

This policy keeps regression results separate from evidence about detection accuracy. Every report identifies the dataset tier, phase, engine commit, scorer, input manifest, and scoring policy.

## Dataset tiers

1. **Self-authored regression** is Kayfabe's existing corpus and apps, plus future cases written by maintainers who know the rules. It detects regressions; it is not independent accuracy evidence.
2. **Independently authored** apps are written by an author who has never seen Kayfabe's rules, labeled corpus, existing apps, or scorer. The author works from a clean checkout containing only the written application-feature brief. Record the author or system, materials visible during authoring, and date. For a language-model author, record model identifier and training cutoff; if its cutoff is after Kayfabe first became public, the set is not independent.
3. **Third-party real code** includes Juliet, WebGoat.NET, and sampled public repositories. Report each dataset as **seen** when it has informed a rule or analysis change, and **unseen** otherwise. Do not combine these results with independently authored apps.

The author must be isolated; the custodian may be a maintainer if they do not read the sealed contents before scoring. The scorer may be a maintainer. After one phase score, findings may be read, but the set is spent and moves to development status. If no isolated author is available, the independent tier is **not measured**; do not replace it with self-authored apps.

## Authoring, labels, and freeze

The authoring brief names application features and a fixed CWE coverage list. It does not name rule patterns, source/sink APIs, or architecture that mirrors Kayfabe's checks. Require a safe twin for each vulnerable label. Each label records file, line range, CWE, polarity (`vulnerable` or `safe`), and a one-line rationale. Cross-method/file flows also record source and sink locations.

Before scoring, publish a SHA-256 manifest for exact source and labels, the scorer version, engine commit SHA, and scoring policy. A finding matches a vulnerable label only when its CWE matches and its reported location is inside the label's sink region; record the reported path but do not require an exact path match. Safe labels use their marked region and CWE for false-positive counting. Duplicate handling and the unit of analysis are defined by each dataset policy below.

Score each frozen holdout once at its scheduled phase boundary. Log any rule or analysis change informed by held-out findings/results, with affected rules and rationale; retire that set to development for later phases. Preserve historical reports immutably. A missing author, adjudication, or sample-size requirement is **not measured**, never a pass. Revise gates only before a new phase begins and before its holdout score is seen.

## Juliet C# units

For single-file cases, a unit is file × CWE × polarity. Multi-file cases with letter-suffixed variants (22a/b, 51–54, 61, 66–68, 71–75) and the 81 bad/good split use one unit per testcase: family plus variant number, over all its files. A bad unit is TP if a finding of the unit CWE lands in a bad region in any file; a good unit is FP under the same condition for a good region. Freeze the cross-file unit list before measuring. The held half is seen and spent after the CWE-329 scoping fix; it is development evidence.

Gates use the CLI default confidence threshold, currently `low` (all findings). Report `medium` and higher alongside it, but do not use those thresholds to decide gates. Change the gate threshold only at a phase boundary before scoring that phase.

## WebGoat.NET

Adjudicate every current finding as true positive, false positive, or unresolved before using precision results. Record missed known vulnerabilities separately. Use two adjudicators per finding; record their independent labels, agreement, and how disagreements were resolved. WebGoat.NET is seen and excluded from the public-repository sample.

## Public repository sample

Freeze 30–50 eligible repositories and exact revisions before scanning. Target ASP.NET application code, require declared minimum age/activity and a permissive license, and exclude forks, generated samples/templates, eShop, and WebGoat.NET. Record eligibility criteria and rationale. Adjudicate approximately 150 findings stratified by rule, with two adjudicators per finding and a recorded disagreement process. Report per-rule estimates, sample sizes, and intervals; this is an estimate, not a census.

Compute overall precision with weights proportional to each rule's finding count in the frozen sample. The precision gate is the lower bound of a 95% Wilson interval, which must be at least 80%. Per-rule estimates and intervals are reported but do not independently gate a phase. Do not use scanner output alone to assign labels.

## Phase gates

- Juliet cross-file testcase recall is at least 60%, shown separately from overall Juliet. Juliet is seen development data; this measures progress, not independent accuracy.
- Existing self-authored .NET development apps have zero false positives.
- The independently authored holdout is frozen and scored once at its designated phase boundary; it is not a tuning target afterward.
- Public-repository sampled precision meets the weighted Wilson lower-bound gate above.
- Every claimed FP reduction uses the same labeled units and policy, and reports absolute FP counts and precision alongside recall.
- A phase that misses a measured gate does not ship as default behavior. Keep its changes behind an explicit opt-in with the missed gate in release notes, or do not ship them.

## Existing dataset classifications

The authoritative records are in [`dotnet-datasets.json`](dotnet-datasets.json). Own .NET apps, including prior `HELD-OUT.sha256` content, are self-authored regression data; prior held-out scores are not blind. Both Juliet halves are seen third-party data, and the held half is retired. eShop and WebGoat.NET are seen third-party data and excluded from public-repository sampling. The independent holdout and public sample are not measured until isolation, freeze, and adjudication requirements are met.
