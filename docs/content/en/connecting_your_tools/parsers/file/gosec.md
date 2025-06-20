---
title: "Gosec Scanner"
toc_hide: true
---
Import Gosec Scanner findings in JSON format.

### Sample Scan Data
Sample Gosec Scanner scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/gosec).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these hashcode fields:

- title
- cwe
- line
- file path
- description
