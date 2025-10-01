---
title: "Checkmarx CxFlow SAST"
toc_hide: true
---

CxFlow is a Spring Boot application written by Checkmarx that enables initiations of scans and result orchestration.
CxFlow support interactive with various Checkmarx product.
This parser support JSON format export by bug tracker.

```
#YAML
cx-flow:
  bug-tracker:Json
  
#CLI
--cx-flow.bug-tracker=json  
```

- `Checkmarx CxFlow SAST`: JSON report from Checkmarx Cxflow.

### Sample Scan Data
Sample Checkmarx CxFlow SAST scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/checkmarx_cxflow_sast).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln id from tool
- file path
- line
