---
title: "Snyk Code"
toc_hide: true
aliases:
  - "/en/connecting_your_tools/parsers/file/snyk_code/"
---
Snyk output file (snyk code test \--sarif \> snyk.json) can be imported in JSON SARIF format. 

### Sample Scan Data
Sample Snyk Code scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/snyk_code).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](/triage_findings/finding_deduplication/about_deduplication/):

- vuln id from tool
- file path
