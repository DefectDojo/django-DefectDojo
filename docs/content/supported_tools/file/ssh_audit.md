---
title: "SSH Audit"
toc_hide: true
---
Import JSON output of ssh_audit report. See <https://github.com/jtesta/ssh-audit>

### Sample Scan Data
Sample SSH Audit scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/ssh_audit).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file path
- description
