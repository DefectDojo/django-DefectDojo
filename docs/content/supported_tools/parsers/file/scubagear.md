---
title: "CISA ScubaGear"
toc_hide: true
---
Import the CISA ScubaGear action plan in CSV format. ScubaGear assesses a Microsoft 365
tenant against the CISA SCuBA secure configuration baselines.

Run an assessment and import the resulting `ActionPlan.csv`:

```
Invoke-SCuBA -ProductNames aad, defender, exo, sharepoint, teams
```

The action plan holds the controls that did not pass. ScubaGear also writes per-product JSON
reports, but those are UTF-16 encoded and hold the full pass/fail set; the action plan is the
artifact intended for remediation tracking.

### Severity Mapping
ScubaGear reports no severity. Each baseline control carries a criticality — `Shall` is
mandatory, `Should` is recommended — and a result. DefectDojo derives severity from the
pair:

| Result | Criticality | DefectDojo severity |
| --- | --- | --- |
| Fail | Shall | High |
| Fail | Should | Medium |
| Warning | any | Low |
| Pass | any | not imported |

Controls whose criticality ends in `Not-Implemented` are ones ScubaGear does not yet
evaluate, and describe a gap in the tool rather than in the tenant, so they are not imported.

The `Requirement` and `Details` columns are rendered for the HTML report and contain markup,
which is stripped before the text reaches the Finding.

### Sample Scan Data
Sample ScubaGear scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/scubagear).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- severity
