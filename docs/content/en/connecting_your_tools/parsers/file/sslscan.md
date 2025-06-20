---
title: "Sslscan"
toc_hide: true
---
Import XML output of sslscan report.

### Sample Scan Data
Sample Sslscan scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/sslscan).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these hashcode fields:

- title
- cwe
- line
- file path
- description
