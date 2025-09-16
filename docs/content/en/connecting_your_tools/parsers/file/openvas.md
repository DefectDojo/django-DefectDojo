---
title: "OpenVAS Parser"
toc_hide: true
---
You can either upload the exported results of an OpenVAS Scan in a .csv or .xml format.

### Sample Scan Data
Sample OpenVAS scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/openvas).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file path
- description

### Parser V2 Changes
Version 2 comes with multiple improvments:
- Increased parsing Consistensy between the xml and csv parser
- Combined findings where the only differences are in fields that can’t be rehashed due to inconsistent values between scans e.g fields with timestamps or packet ids.
- Parser now combines multiple identical findings with different endpoints into one findings with multiple endpoints (instead of multiple findings with one endpoint each)
