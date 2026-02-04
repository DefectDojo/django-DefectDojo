---
title: "Bugcrowd"
toc_hide: true
---
Import Bugcrowd results in CSV format.

### Sample Scan Data
Sample Bugcrowd scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/bugcrowd).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file path
- description
