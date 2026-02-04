---
title: "AWS Prowler Scanner"
toc_hide: true
---
Prowler file can be imported as a CSV (`-M csv`) or JSON (`-M json`) file.

### Sample Scan Data
Sample AWS Prowler Scanner scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/aws_prowler).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file path
- description
