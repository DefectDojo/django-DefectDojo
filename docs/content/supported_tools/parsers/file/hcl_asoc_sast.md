---
title: "HCL AppScan on Cloud SAST"
toc_hide: true
---
HCL Appscan on Cloud can export the results in PDF, XML and CSV formats but this parser only supports the import of XML generated from HCL Appscan on Cloud for SAST scans.

### Sample Scan Data
Sample HCL AppScan on Cloud SAST scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/hcl_asoc_sast).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- file path
- line
- severity
