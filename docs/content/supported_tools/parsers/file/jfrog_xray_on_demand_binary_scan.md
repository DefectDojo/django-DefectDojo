---
title: "JFrog Xray On Demand Binary Scan"
toc_hide: true
---
Import the JSON format for the \"JFrog Xray On Demand Binary Scan\" file. Use this importer for Xray version 3.X

JFrog file documentation:

https://jfrog.com/help/r/jfrog-cli/on-demand-binary-scan

### Sample Scan Data
Sample JFrog Xray On Demand Binary Scan scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/jfrog_xray_on_demand_binary_scan).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- component name
- component version
