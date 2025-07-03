---
title: "JFrogXRay"
toc_hide: true
---
Import the JSON format for the \"Security Export\" file. Use this importer for Xray version 2.X

### Sample Scan Data
Sample JFrogXRay scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/jfrogxray).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these hashcode fields:

- title
- description
- component name
- component version
