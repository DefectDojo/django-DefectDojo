---
title: "Qualys Infrastructure Scan (WebGUI XML)"
toc_hide: true
---
Qualys WebGUI output files can be imported in XML format.

### Sample Scan Data
Sample Qualys Infrastructure Scan (WebGUI XML) scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/qualys_infrascan_webgui).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file path
- description
