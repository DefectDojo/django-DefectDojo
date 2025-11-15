---
title: "Netsparker"
toc_hide: true
---

[Netsparker has now become Invicti](https://www.invicti.com/blog/news/netsparker-is-now-invicti-signaling-a-new-era-for-modern-appsec/). Please plan to migrate automation scripts to use the [Invicti Scan](../invicti) type.

Vulnerabilities List - JSON report

### Sample Scan Data

Sample Netsparker scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/netsparker).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file path
- description
