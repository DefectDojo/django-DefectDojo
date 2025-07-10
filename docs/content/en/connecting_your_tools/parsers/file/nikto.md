---
title: "Nikto"
toc_hide: true
---
Nikto web server scanner - https://cirt.net/Nikto2

The current parser support 3 sources:
 - XML output (old)
 - new XML output (with nxvmlversion=\"1.2\" type)
 - JSON output

See: https://github.com/sullo/nikto

### Sample Scan Data
Sample Nikto scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/nikto).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file path
- description
