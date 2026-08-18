---
title: "Quark-Engine"
toc_hide: true
---
Import Quark-Engine reports in JSON format. Quark-Engine scores Android applications by
detecting behaviours ("crimes") such as sending device location over SMS, rather than by
matching known vulnerabilities.

Generate a report with:

```
quark -a sample.apk -s -o quark-report.json
```

### Severity Mapping
Quark-Engine assigns no severity. Each detected behaviour carries a confidence expressing
how many of Quark's five detection stages matched — requested permission, native API call,
API combination, calling sequence, and shared register — in 20% increments. A confidence of
100% means every required API was used *and* a data flow between them was confirmed; 80%
means the APIs were present but no data flow was found.

DefectDojo derives severity from that confidence:

| Quark confidence | DefectDojo severity |
| --- | --- |
| 100% | High |
| 80% | Medium |
| 40–60% | Low |
| 0–20% | Info |

The report's own `threat_level` and `total_score` describe the APK as a whole rather than
any single behaviour, so they are not mapped onto individual Findings.

### Sample Scan Data
Sample Quark-Engine scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/quark_engine).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- component_name
- vuln_id_from_tool
