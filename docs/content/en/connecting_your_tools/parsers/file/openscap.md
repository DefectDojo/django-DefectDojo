---
title: "Openscap Vulnerability Scan"
toc_hide: true
---
Import Openscap Vulnerability Scan in XML formats.

### Sample Scan Data
Sample Openscap Vulnerability Scan scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/openscap).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these hashcode fields:

- title
- cwe
- line
- file path
- description
