---
title: "OSV Scanner"
toc_hide: true
---
Use [OSV-Scanner](https://github.com/google/osv-scanner) to find existing vulnerabilities affecting your project's dependencies.

### Sample Scan Data
Sample OSV Scanner output can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/osv_scanner).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- description
- severity
