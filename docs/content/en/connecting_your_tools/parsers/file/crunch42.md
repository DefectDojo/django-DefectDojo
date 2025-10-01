---
title: "Crunch42 Scan"
toc_hide: true
---
Import JSON findings from Crunch42 vulnerability scan tool.

### Sample Scan Data
Sample Crunch42 Scan scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/crunch42).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file path
- description
