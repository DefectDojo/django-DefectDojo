---
title: "Staticcheck"
toc_hide: true
---
Import Staticcheck reports in JSON format. Staticcheck is the Go static analysis suite, made up
of four analysers: `staticcheck` itself for correctness problems, `gosimple` for code that can be
written more simply, `stylecheck` for style and naming, and `quickfix` for mechanical
refactorings, plus an `unused` pass for dead identifiers.

Generate a report with:

```
staticcheck -f json ./... > staticcheck.json
```

Note that `-f json` writes one JSON object per line rather than a single JSON document, which is
what this parser expects.

Each diagnostic becomes one Finding, titled with the check code and the message, and located at
the file and line Staticcheck reported. The check code is stored in `vuln_id_from_tool`, so a
team can silence or track an individual check.

### Severity Mapping
Staticcheck has no severity scale. Its JSON does carry a `severity` key, but in practice every
reported diagnostic is `error`: the field exists to distinguish reported problems from ones a
`//lint:ignore` directive silenced, not important ones from unimportant ones. Defaulting the
whole report to one middle value would throw away the one real distinction Staticcheck does
make, which is *which analyser* raised the diagnostic. That is encoded in the check code prefix
and [documented in the checks list](https://staticcheck.dev/docs/checks/), so severity is derived
from it:

| Check code | Analyser | DefectDojo severity |
| --- | --- | --- |
| `SA…` | staticcheck — correctness problems and outright bugs | Medium |
| `U1…` | unused — unreachable or unused identifiers | Low |
| `S1…` | gosimple — could be written more simply | Info |
| `ST1…` | stylecheck — style and naming | Info |
| `QF1…` | quickfix — refactorings, offered rather than advised | Info |
| anything else | unrecognised prefix | Low |

`SA` checks are Medium rather than High because they are real defects but not, on their own,
demonstrated vulnerabilities: Staticcheck reasons about the code, not about reachability from an
attacker. The three cosmetic analysers are Info because acting on them is a preference, not a
fix.

Two cases are handled outside that table:

- A diagnostic silenced by `//lint:ignore` (only present when running with `-show-ignored`) is
  imported as Info and marked as a false positive, since the codebase has already made a decision
  about it.
- A `compile` record is not a lint result at all: it means the package did not build, so it was
  never analysed. That is imported as High, because the important fact is that the scan was blind
  to that package rather than that it was clean.

Staticcheck reports no CWE values, so imported Findings have no CWE.

### Sample Scan Data
Sample Staticcheck scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/staticcheck).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- file_path
- line
