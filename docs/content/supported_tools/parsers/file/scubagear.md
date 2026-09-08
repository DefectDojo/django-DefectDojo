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

Two artifacts are supported, each with its own scan type:

- **ScubaGear Scan** — the `ActionPlan.csv`, holding only the controls that did not pass.
  Written as UTF-8 with a byte order mark.
- **ScubaGear Report Scan** — a per-product JSON report from `IndividualReports/`, holding the
  full pass and fail set. Written as UTF-16; the encoding is detected from the byte order mark,
  so no conversion is needed before import.

Both are graded identically; the JSON simply carries more, since passing controls are present
in the source and dropped on import.

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
