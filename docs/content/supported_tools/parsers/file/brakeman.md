---
title: "Brakeman Scan"
toc_hide: true
---
Import Brakeman Scanner findings in JSON format.

### Sample Scan Data
Sample Brakeman Scan scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/brakeman).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file path
- description
