---
title: "Detect-secrets"
toc_hide: true
---
Import of JSON report from <https://github.com/Yelp/detect-secrets>

### Sample Scan Data
Sample Detect-secrets scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/detect_secrets).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file path
- description
