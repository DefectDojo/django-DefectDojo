---
title: "NeuVector (compliance)"
toc_hide: true
---
Imports compliance scans returned by REST API.

### Sample Scan Data
Sample NeuVector (compliance) scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/neuvector).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these hashcode fields:

- title
- severity
- component name
- component version
