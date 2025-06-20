---
title: "Retire.js"
toc_hide: true
---
Retire.js JavaScript scan (\--js) output file can be imported in JSON format.

### Sample Scan Data
Sample Retire.js scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/retirejs).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these hashcode fields:

- title
- cwe
- line
- file path
- description
