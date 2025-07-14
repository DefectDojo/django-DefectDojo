---
title: "GitLab Dependency Scanning Report"
toc_hide: true
---
Import Dependency Scanning Report vulnerabilities in JSON format: https://docs.gitlab.com/ee/user/application_security/dependency_scanning/#reports-json-format

### Sample Scan Data
Sample GitLab Dependency Scanning Report scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/gitlab_dep_scan).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- vulnerability ids
- file path
- component name
- component version
