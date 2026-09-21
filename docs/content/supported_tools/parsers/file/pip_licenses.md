---
title: "pip-licenses"
toc_hide: true
---
Import pip-licenses reports in JSON format. pip-licenses inventories the licence of every
installed Python distribution.

Generate a report with:

```
pip-licenses --format=json > pip-licenses.json
```

### Scope and Severity
pip-licenses is a **compliance inventory, not a vulnerability scanner**. It reports what is
installed and under which licence, and judges nothing — so every package it lists becomes a
Finding, and they are informational by default.

The one exception is a distribution whose licence pip-licenses could not determine. An
undetermined licence is itself a compliance gap, so those are raised to **Low**:

| pip-licenses result | DefectDojo severity |
| --- | --- |
| Licence declared | Info |
| `UNKNOWN` / no licence metadata | Low |

DefectDojo does not decide which licences are acceptable for your organisation. If you need
copyleft or licence-policy enforcement, filter or triage on the licence recorded in
`vuln_id_from_tool` after import.

### Sample Scan Data
Sample pip-licenses scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/pip_licenses).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- component_name
- component_version
- vuln_id_from_tool
