---
title: "PMapper"
toc_hide: true
---
Import PMapper (Principal Mapper) reports in JSON format. PMapper builds a graph of the IAM
principals in an AWS account, works out which principals can reach which others, and reports the
privilege escalation paths that graph exposes.

Generate a report with:

```
pmapper --account <account> graph create
pmapper --account <account> analysis --output-type json > pmapper.json
```

Each finding in the report becomes one Finding. PMapper's own `impact` and `recommendation` are
carried across to the Finding's impact and mitigation fields rather than being flattened into the
description, and the account analysed becomes the component so findings from several accounts stay
distinguishable in one product.

### Severity Mapping
PMapper grades its own findings. Its risk checks assign a severity string when they build a finding,
and those are used directly:

| PMapper severity | DefectDojo severity |
| --- | --- |
| Critical | Critical |
| High | High |
| Medium | Medium |
| Low | Low |
| Info / Informational | Info |

PMapper's own checks currently use High, Medium and Low; Critical and Info are mapped so a custom or
future check that uses them is not silently downgraded. A severity string this list does not
recognise falls back to Medium rather than to the lowest or highest rung, so an unexpected value
cannot quietly hide a finding or inflate it.

### Sample Scan Data
Sample PMapper scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/pmapper).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- component_name
