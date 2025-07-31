---
title: "Mobsfscan"
toc_hide: true
---
Import JSON report from <https://github.com/MobSF/mobsfscan>

### Sample Scan Data
Sample Mobsfscan scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/mobsfscan).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- cwe
- file path
- description
