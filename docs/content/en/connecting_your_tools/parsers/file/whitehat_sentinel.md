---
title: "WhiteHat Sentinel"
toc_hide: true
---
WhiteHat Sentinel output from api/vuln/query_site can be imported in JSON format.

### Sample Scan Data
Sample WhiteHat Sentinel scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/whitehat_sentinel).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file path
- description
