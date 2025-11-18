---
title: "Snyk"
toc_hide: true
---
Snyk output file (snyk test \--json \> snyk.json) can be imported in
JSON format. Only SCA (Software Composition Analysis) report is supported (SAST report not supported yet).

### Sample Scan Data
Sample Snyk scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/snyk).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln id from tool
- file path
- component name
- component version
