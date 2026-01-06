---
title: "Rapplex Scan"
toc_hide: true
---
Import JSON report of [Rapplex - Web Application Security Scanner](https://rapplex.com)


### Sample Scan Data
Sample Rapplex scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/rapplex).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- endpoints
- severity
