---
title: "NeuVector (REST)"
toc_hide: true
---
JSON output of /v1/scan/{entity}/{id} endpoint

### Sample Scan Data
Sample NeuVector (REST) scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/neuvector_compliance).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these hashcode fields:

- title
- vuln id from tool
- description
