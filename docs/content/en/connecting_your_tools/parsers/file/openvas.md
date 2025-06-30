---
title: "OpenVAS Parser"
toc_hide: true
---
You can either upload the exported results of an OpenVAS Scan in a .csv or .xml format.

### Sample Scan Data
Sample OpenVAS scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/openvas).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these hashcode fields:

- title
- cwe
- line
- file path
- description
