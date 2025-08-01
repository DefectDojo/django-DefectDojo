---
title: "Burp REST API"
toc_hide: true
---
Import Burp REST API scan data in JSON format (/scan/[task_id] endpoint).

### Sample Scan Data
Sample Burp REST API scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/burp_api).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file path
- description
