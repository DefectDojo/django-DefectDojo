---
title: "CISA ScubaGoggles"
toc_hide: true
---
Import CISA ScubaGoggles reports in JSON format. ScubaGoggles assesses a Google Workspace
tenant against the CISA SCuBA secure configuration baselines.

Run an assessment and import the resulting `ScubaResults_*.json`:

```
scubagoggles gws -o output
```

### Severity Mapping
ScubaGoggles reports no severity. Each baseline policy carries a criticality — `Shall` is
mandatory, `Should` is recommended — and a result. DefectDojo derives severity from the
pair:

| Result | Criticality | DefectDojo severity |
| --- | --- | --- |
| Fail | Shall | High |
| Fail | Should | Medium |
| Warning | any | Low |
| Pass | any | not imported |
| N/A, No events found | any | not imported |

Baselines whose criticality ends in `Not-Implemented` are ones ScubaGoggles does not yet
evaluate. They describe a gap in the tool rather than in the tenant, so they are not
imported.

The `Requirement` and `Details` fields are rendered for the HTML report and contain markup,
which is stripped before the text reaches the Finding.

### Sample Scan Data
Sample ScubaGoggles scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/scubagoggles).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- component_name
