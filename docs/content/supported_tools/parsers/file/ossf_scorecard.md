---
title: "OpenSSF Scorecard"
toc_hide: true
---
Import OpenSSF Scorecard JSON. Scorecard grades a repository's supply chain posture across a
set of independent checks — branch protection, pinned dependencies, token permissions, SAST
coverage and others.

Generate a report with:

```
scorecard --repo=github.com/<org>/<repo> --format=json > scorecard.json
```

Scorecard also publishes results for many public repositories through its API, which returns
the same JSON:

```
curl https://api.securityscorecards.dev/projects/github.com/<org>/<repo>
```

Scorecard can additionally emit SARIF, which DefectDojo's generic SARIF parser already
handles. Use this parser for the native JSON, which carries the numeric score per check that
SARIF does not.

### Severity Mapping
Scorecard scores each check from 0 to 10 rather than assigning severities, and DefectDojo
derives severity from how far the check falls short:

| Scorecard score | DefectDojo severity |
| --- | --- |
| 0–3 | High |
| 4–6 | Medium |
| 7–9 | Low |
| 10 | not imported |
| -1 | not imported |

A score of -1 means the check could not reach a conclusion, usually because it lacks the
access or metadata it needs. That is not the same as a failure, so it is not imported.

### Sample Scan Data
Sample OpenSSF Scorecard scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/ossf_scorecard).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- component_name
