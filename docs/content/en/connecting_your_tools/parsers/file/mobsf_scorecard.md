---
title: "MobSF Scorecard Scanner"
toc_hide: true
---
Export a JSON file using the API, api/v1/report_json.

### Sample Scan Data
Sample MobSF Scorecard Scanner scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/mobsf_scorecard).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- description
- severity
