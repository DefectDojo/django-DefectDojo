---
title: "Veracode SourceClear"
toc_hide: true
---
Import Project CSV or JSON report

### Sample Scan Data
Sample Veracode SourceClear scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/veracode_sca).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these hashcode fields:

- title
- vulnerability ids
- component name
- component version
- severity
