---
title: "Tenable"
toc_hide: true
---
Reports can be imported in the CSV, and .nessus (XML) report formats.
Legacy Nessus and Nessus WAS reports are supported

### Sample Scan Data
Sample Tenable scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/tenable).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these hashcode fields:

- title
- severity
- vulnerability ids
- cwe
- description
