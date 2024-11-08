---
title: "KrakenD Audit Scan"
toc_hide: true
---
Import KrakenD Audit Scan results in JSON format. You can use the following command to audit the KrakenD configuration which then can be uploaded to DefectDojo: 
```
krakend audit -c krakend.json -f "{{ marshal . }}" >> recommendations.json
```

### Sample Scan Data
Sample KrakenD Audit scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/krakend_audit).