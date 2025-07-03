---
title: "Visual Code Grepper (VCG)"
toc_hide: true
---
VCG output can be imported in CSV or Xml formats.

### Sample Scan Data
Sample Visual Code Grepper (VCG) scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/vcg).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these hashcode fields:

- title
- cwe
- line
- file path
- description
