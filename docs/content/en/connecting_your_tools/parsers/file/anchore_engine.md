---
title: "Anchore-Engine"
toc_hide: true
---

### File Types
DefectDojo parser accepts a .json file.

Using the [Anchore CLI](https://docs.anchore.com/current/docs/using/cli_usage/images/inspecting_image_content/) is the most reliable way to generate an Anchore report which DefectDojo can parse. When generating a report with the Anchore CLI, please use the following command to ensure complete data: `anchore-cli --json image vuln <image:tag> all`

### Acceptable JSON Format
All properties are strings and are required by the parser. As the parser evolved, two anchore engine parser JSON formats are present till now. Both ([old](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/anchore_engine/many_vulns.json) / [new](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/anchore_engine/new_format_issue_11552.json)) are supported.

### Sample Scan Data
Sample Anchore-Engine scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/anchore_engine).