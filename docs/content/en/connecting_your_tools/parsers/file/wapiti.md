---
title: "Wapiti Scan"
toc_hide: true
---
Import XML report.

### Sample Scan Data
Sample Wapiti Scan scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/wapiti).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these hashcode fields:

- title
- cwe
- line
- file path
- description
