---
title: "Anchore Enterprise Policy Check"
toc_hide: true
---
Anchore-CLI JSON policy check report format.

### Sample Scan Data
Sample Anchore Enterprise Policy Check scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/anchore_enterprise).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- component name
- file path
