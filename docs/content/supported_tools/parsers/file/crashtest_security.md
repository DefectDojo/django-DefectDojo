---
title: "Crashtest Security"
toc_hide: true
aliases:
  - "/en/connecting_your_tools/parsers/file/crashtest_security/"
---
Import JSON Report Import XML Report in JUnit Format

### Sample Scan Data
Sample Crashtest Security scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/crashtest_security).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](/triage_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file path
- description
