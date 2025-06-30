---
title: "Semgrep JSON Report"
toc_hide: true
---
Import Semgrep output (--json)

### Sample Scan Data
Sample Semgrep JSON Report scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/semgrep).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these hashcode fields:

- title
- cwe
- line
- file path
- description
