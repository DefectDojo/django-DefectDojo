---
title: "MobSF Scanner"
toc_hide: true
---
"Mobsfscan Scan" has been merged into the "MobSF Scan" parser. The "Mobsfscan Scan" scan_type has been retained to keep deduplication working for existing Tests, but users are encouraged to move to the "MobSF Scan" scan_type.

Export a JSON file using the API, api/v1/report\_json and import it to Defectdojo or import a JSON report from <https://github.com/MobSF/mobsfscan>

### Sample Scan Data
Sample MobSF Scanner scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/mobsf).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- description
- severity
