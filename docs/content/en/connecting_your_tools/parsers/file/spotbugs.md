---
title: "SpotBugs"
toc_hide: true
---
XML report of textui cli.

### Sample Scan Data
Sample SpotBugs scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/spotbugs).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these hashcode fields:

- cwe
- severity
- file path
- line
