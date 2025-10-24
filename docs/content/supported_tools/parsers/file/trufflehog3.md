---
title: "Trufflehog3"
toc_hide: true
---
JSON Output of Trufflehog3, a fork of TruffleHog located at https://github.com/feeltheajf/truffleHog3

### Sample Scan Data
Sample Trufflehog3 scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/trufflehog3).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file path
- description
