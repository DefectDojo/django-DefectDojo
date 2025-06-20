---
title: "Clair Scan"
toc_hide: true
---
You can import JSON reports of Docker image vulnerabilities found by a Clair scan or the Clair Klar client.

### Sample Scan Data
Sample Clair Scan scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/clair).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these hashcode fields:

- title
- vulnerability ids
- description
- severity
