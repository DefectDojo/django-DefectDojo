---
title: "HuskyCI Report"
toc_hide: true
---
Import JSON reports from
[HuskyCI](<https://github.com/globocom/huskyCI>)

### Sample Scan Data
Sample HuskyCI Report scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/huskyci).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these hashcode fields:

- title
- cwe
- line
- file path
- description
