---
title: "GitLab DAST Report"
toc_hide: true
---
GitLab DAST Report in JSON format (option --json)

### Sample Scan Data
Sample GitLab DAST Report scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/gitlab_dast).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file path
- description
