---
title: "Acunetix Scanner"
toc_hide: true
---
This parser imports the Acunetix Scanner with xml output or Acunetix 360 Scanner with JSON output.

### Sample Scan Data
Sample Acunetix Scanner scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/acunetix).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- description
