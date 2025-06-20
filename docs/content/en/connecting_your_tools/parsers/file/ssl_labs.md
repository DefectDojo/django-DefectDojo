---
title: "SSL Labs"
toc_hide: true
---
JSON Output of ssllabs-scan cli.

### Sample Scan Data
Sample SSL Labs scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/ssl_labs).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these hashcode fields:

- title
- cwe
- line
- file path
- description
