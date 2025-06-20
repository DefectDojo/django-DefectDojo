---
title: "Sonatype"
toc_hide: true
---
JSON output.

### Sample Scan Data
Sample Sonatype scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/sonatype).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these hashcode fields:

- title
- cwe
- file path
- component name
- component version
- vulnerability ids
