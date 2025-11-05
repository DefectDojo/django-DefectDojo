---
title: "kubeHunter Scanner"
toc_hide: true
---
Import JSON reports of kube-hunter scans. Use "kube-hunter --report json" to produce the report in json format.

### Sample Scan Data
Sample kubeHunter Scanner scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/kubehunter).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- description
