---
title: "Qualys Webapp Scan"
toc_hide: true
---
Qualys WebScan output files can be imported in XML format.

### Sample Scan Data
Sample Qualys Webapp Scan scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/qualys_webapp).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these hashcode fields:

- title
- cwe
- line
- file path
- description
