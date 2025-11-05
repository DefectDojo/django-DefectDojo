---
title: "CredScan Report"
toc_hide: true
---
Import CSV credential scanner reports

### Sample Scan Data
Sample CredScan Report scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/cred_scan).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file path
- description
