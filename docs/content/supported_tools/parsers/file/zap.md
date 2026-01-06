---
title: "Zed Attack Proxy"
toc_hide: true
---
ZAP XML report format (with or without requests and responses).

### Sample Scan Data
Sample Zed Attack Proxy scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/zap).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- severity
