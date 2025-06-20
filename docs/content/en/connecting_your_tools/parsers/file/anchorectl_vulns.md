---
title: "AnchoreCTL Vuln Report"
toc_hide: true
---
AnchoreCTLs JSON vulnerability report format

### Sample Scan Data
Sample AnchoreCTL Vuln Report scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/anchorectl_vulns).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these hashcode fields:

- title
- severity
- component name
- component version
- file path
