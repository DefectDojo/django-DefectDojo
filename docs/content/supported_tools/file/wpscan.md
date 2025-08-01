---
title: "Wpscan Scanner"
toc_hide: true
---
Import JSON report.

### Sample Scan Data
Sample Wpscan Scanner scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/wpscan).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- description
- severity
