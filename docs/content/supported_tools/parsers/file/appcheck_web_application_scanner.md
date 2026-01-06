---
title: "AppCheck Web Application Scanner"
toc_hide: true
---
Accepts AppCheck Web Application Scanner output in .json format.

### Sample Scan Data
Sample AppCheck Web Application Scanner scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/appcheck_web_application_scanner).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
