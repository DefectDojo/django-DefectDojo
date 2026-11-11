---
title: "Betterleaks"
toc_hide: true
aliases:
  - "/en/connecting_your_tools/parsers/file/betterleaks/"
---
Import Betterleaks findings in JSON format.

### Sample Scan Data
Sample Betterleaks scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/betterleaks).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](/triage_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file path
- description
