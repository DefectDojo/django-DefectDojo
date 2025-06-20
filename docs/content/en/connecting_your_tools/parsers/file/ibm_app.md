---
title: "IBM AppScan DAST"
toc_hide: true
---
XML file from IBM App Scanner.

### Sample Scan Data
Sample IBM AppScan DAST scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/ibm_app).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these hashcode fields:

- title
- cwe
- line
- file path
- description
