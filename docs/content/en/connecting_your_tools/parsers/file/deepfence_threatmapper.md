---
title: "Deepfence Threatmapper"
toc_hide: true
---
Import compliance, malware, secret, vulnerability reports from [Deepfence Threatmapper](https://github.com/deepfence/ThreatMapper) in XLSX file format. 

### Sample Scan Data
Sample Threatmapper scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/deepfence_threatmapper). In this link are both .xlsx and .csv listed. They contain the same content, but csv can be read in the Browser, but only xlsx is supported by the parser. 

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- description
- severity
