---
title: "OpenVAS Parser V2"
toc_hide: true
---
This is version 2 of the OpenVAS / Greenbone parser.
You can upload your scanns in eighter csv or xml format. For the parser to recognize the difference they have to end with .csv or .xml.

### V2 Changes
Version 2 comes with multiple improvments TODO:
- Using using unique_id_from_tool for deduplication
- Increased parsing Consistensy between the xml and csv parser
- Combined findings where the only differences are in fields that can’t be rehashed due to inconsistent values between scans e.g fields with timestamps or packet ids.
- Parser now combines multiple identical findings with different endpoints into one findings with multiple endpoints (instead of multiple findings with one endpoint each)

### Sample Scan Data
Sample OpenVAS scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/openvas).
