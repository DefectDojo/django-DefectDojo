---
title: "Terrascan"
toc_hide: true
---
Import JSON output of terrascan scan report <https://github.com/accurics/terrascan>

### Sample Scan Data
Sample Terrascan scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/terrascan).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these hashcode fields:

- vuln id from tool
- title
- severity
- file path
- line
- component name
