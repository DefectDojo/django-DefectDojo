---
title: "Node Security Platform"
toc_hide: true
aliases:
  - "/en/connecting_your_tools/parsers/file/nsp/"
---
Node Security Platform (NSP) output file can be imported in JSON format.

### Sample Scan Data
Sample Node Security Platform scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/nsp).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](/triage_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file path
- description
