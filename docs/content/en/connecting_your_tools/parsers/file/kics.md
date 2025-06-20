---
title: "KICS Scanner"
toc_hide: true
---
Import of JSON report from <https://github.com/Checkmarx/kics>

### Sample Scan Data
Sample KICS Scanner scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/kics).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these hashcode fields:

- file path
- line
- severity
- description
- title
