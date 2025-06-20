---
title: "kube-bench Scanner"
toc_hide: true
---
Import JSON reports of Kubernetes CIS benchmark scans.

### Sample Scan Data
Sample kube-bench Scanner scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/kubebench).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these hashcode fields:

- title
- vuln id from tool
- description
