---
title: "Tenable"
toc_hide: true
aliases:
  - "/en/connecting_your_tools/parsers/file/tenable/"
---
Reports can be imported in the CSV, and .nessus (XML) report formats.
Legacy Nessus and Nessus WAS reports are supported

### Sample Scan Data
Sample Tenable scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/tenable).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](/triage_findings/finding_deduplication/about_deduplication/):

- title
- severity
- vulnerability ids
- cwe
- description
