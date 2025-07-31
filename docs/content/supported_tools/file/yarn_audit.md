---
title: "Yarn Audit"
toc_hide: true
---
Import Yarn Audit scan report in JSON format. Use something like `yarn audit --json > yarn_report.json`.

### Sample Scan Data
Sample Yarn Audit scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/yarn_audit).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- file path
- vulnerability ids
- cwe
