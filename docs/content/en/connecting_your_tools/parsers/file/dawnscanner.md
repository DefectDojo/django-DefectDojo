---
title: "DawnScanner"
toc_hide: true
---
Import report in JSON generated with -j option

### Sample Scan Data
Sample DawnScanner scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/dawnscanner).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these hashcode fields:

- title
- cwe
- line
- file path
- description
