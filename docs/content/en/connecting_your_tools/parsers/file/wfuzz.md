---
title: "Wfuzz JSON importer"
toc_hide: true
---
Import the result of Wfuzz (https://github.com/xmendez/wfuzz) if you export in JSON the result (`wfuzz  -o json -f myJSONReport.json,json`).

The return code matching are directly put in Severity as follow(this is hardcoded in the parser actually).

HTTP Return Code | Severity
-----------------|---------
missing          |  Low
200 - 299        |  High
300 - 399        |  Low
400 - 499        |  Medium
>= 500           |  Low

### Sample Scan Data
Sample Wfuzz JSON importer scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/wfuzz).