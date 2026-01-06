---
title: "JFrog Xray API Summary Artifact Scan"
toc_hide: true
---

### File Types
Accepts a JSON File, generated from the JFrog Artifact Summary API Call.

### Sample Scan Data / Unit Tests
Sample JFrog Xray API Summary Artifact Scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/jfrog_xray_api_summary_artifact).

### Link To Tool
See JFrog Documentation: https://jfrog.com/help/r/jfrog-rest-apis/summary

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file path
- description
