---
title: "ORT evaluated model Importer"
toc_hide: true
---
Import Outpost24 endpoint vulnerability scan in XML format.

### Sample Scan Data
Sample ORT evaluated model Importer scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/ort).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these hashcode fields:

- title
- cwe
- line
- file path
- description
