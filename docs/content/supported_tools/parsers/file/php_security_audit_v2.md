---
title: "PHP Security Audit v2"
toc_hide: true
---
Import PHP Security Audit v2 Scan in JSON format.

### Sample Scan Data
Sample PHP Security Audit v2 scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/php_security_audit_v2).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file path
- description
