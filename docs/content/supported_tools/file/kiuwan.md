---
title: "Kiuwan Scanner (SAST)"
toc_hide: true
---
Import Kiuwan SAST Scan in CSV format. Export as CSV Results on Kiuwan, or via the [Kiuwan REST API](https://static.kiuwan.com/rest-api/kiuwan-rest-api.html) endpoint `vulnerabilities/export` (type=csv).

### Sample Scan Data
Sample Kiuwan Scanner scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/kiuwan).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- description
- severity
- component name
- component version
- cwe
