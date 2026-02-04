---
title: "Progpilot"
toc_hide: true
---
This parser imports the Progpilot SAST JSON output. The scanner can be found [here](https://github.com/designsecurity/progpilot).

### Sample Scan Data
Sample Progpilot Parser scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/progpilot).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file path
- description
