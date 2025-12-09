---
title: "docker-bench-security Scanner"
toc_hide: true
---
Import JSON reports of OWASP [docker-bench-security](https://github.com/docker/docker-bench-security).
docker-bench-security is a script that make tests based on [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker/).

### Sample Scan Data
Sample docker-bench-security Scanner scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/dockerbench).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file path
- description
