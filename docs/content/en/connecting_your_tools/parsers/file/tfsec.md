---
title: "TFSec"
toc_hide: true
---
Import of JSON report from <https://github.com/tfsec/tfsec>

### Sample Scan Data
Sample TFSec scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/tfsec).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these hashcode fields:

- severity
- vuln id from tool
- file path
- line
