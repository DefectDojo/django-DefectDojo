---
title: "GitLab Container Scan"
toc_hide: true
---
GitLab Container Scan report file can be imported in JSON format (option --json)

### Sample Scan Data
Sample GitLab Container Scan scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/gitlab_container_scan).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file path
- description
