---
title: "Slither"
toc_hide: true
---
Import Slither reports in JSON format. Slither is a static analyser for Solidity smart
contracts.

Generate a report with:

```
slither . --json slither.json
```

Slither needs a matching `solc` on the path, which `solc-select` can manage.

### Severity Mapping
Slither reports two independent axes per detector result: **impact**, which is the severity
axis, and **confidence**, which describes how sure Slither is that the result is real.
DefectDojo maps impact and records confidence in the description rather than blending them:

| Slither impact | DefectDojo severity |
| --- | --- |
| High | High |
| Medium | Medium |
| Low | Low |
| Informational | Info |
| Optimization | Info |

Slither's `id` is a stable hash of the result's content and is stored as
`unique_id_from_tool`, so a result tracks across re-imports even when line numbers move.

### Sample Scan Data
Sample Slither scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/slither).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln_id_from_tool
- file_path
- line
