---
title: "Wfuzz JSON importer"
toc_hide: true
---
Import the result of Wfuzz (https://github.com/xmendez/wfuzz) if you export in JSON the result (`wfuzz  -o json -f myJSONReport.json,json`).

The return code matching are directly put in Severity as follow(this is hardcoded in the parser actually).

HTTP Return Code | Severity
-----------------|---------
200              |  High
302              |  Low
401              |  Medium
403              |  Medium
404              |  Medium
407              |  Medium
500              |  Low

### Sample Scan Data
Sample Wfuzz JSON importer scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/wfuzz).