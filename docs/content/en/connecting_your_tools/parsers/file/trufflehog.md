---
title: "Trufflehog"
toc_hide: true
---
JSON Output of Trufflehog. Supports version 2 and 3 of https://github.com/trufflesecurity/trufflehog

### Sample Scan Data
Sample Trufflehog scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/trufflehog).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- description
- line
