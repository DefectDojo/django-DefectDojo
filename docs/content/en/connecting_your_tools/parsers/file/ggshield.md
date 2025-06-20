---
title: "Ggshield"
toc_hide: true
---
Import [Ggshield](https://github.com/GitGuardian/ggshield) findings in JSON format.

### Sample Scan Data
Sample Ggshield scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/ggshield).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these hashcode fields:

- title
- cwe
- line
- file path
- description
