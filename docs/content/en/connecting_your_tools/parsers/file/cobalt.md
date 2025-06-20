---
title: "Cobalt.io Scan"
toc_hide: true
---
CSV Report

### Sample Scan Data
Sample Cobalt.io Scan scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/cobalt).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these hashcode fields:

- title
- cwe
- line
- file path
- description
