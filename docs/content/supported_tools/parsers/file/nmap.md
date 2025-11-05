---
title: "Nmap"
toc_hide: true
---
XML output (use -oX)

### Sample Scan Data
Sample Nmap scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/nmap).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file path
- description
