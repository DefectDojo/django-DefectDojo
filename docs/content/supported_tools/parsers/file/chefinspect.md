---
title: "Chef Inspect Log"
toc_hide: true
---
Chef Inspect outputs log from https://github.com/inspec/inspec

### File Types
DefectDojo parser accepts Chef Inspect log scan data as a .log or .txt file.

### Sample Scan Data
Sample Chef Inspect logs can be found at https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/chefinspect

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file path
- description
