---
title: "Trivy"
toc_hide: true
---
JSON report of [trivy scanner](https://github.com/aquasecurity/trivy).

### Sample Scan Data
Sample Trivy scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/trivy).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these hashcode fields:

- title
- severity
- vulnerability ids
- cwe
- description
