---
title: "HCL Appscan"
toc_hide: true
---
The HCL Appscan has the possibility to export the results in PDF, XML and CSV formats within the portal. However, this parser only supports the import of XML generated from HCL Appscan on cloud.

### Sample Scan Data
Sample HCL Appscan scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/hcl_appscan).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- description
