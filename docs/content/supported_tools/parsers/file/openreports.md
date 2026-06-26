---
title: "OpenReports"
toc_hide: true
aliases:
 - /en/connecting_your_tools/parsers/file/openreports
---
Import JSON reports from [OpenReports](https://github.com/openreports/reports-api).

### File Types

DefectDojo parser accepts a .json file.

OpenReports JSON files can be exported from Kubernetes clusters using kubectl:

```bash
kubectl get reports -A -ojson > reports.json
```

The parser supports single Report objects, arrays of Reports, or Kubernetes List objects.

### Sample Scan Data

Sample OpenReports scans can be found in the [unittests/scans/openreports directory](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/openreports).
