---
title: "JFrog XRay Unified"
toc_hide: true
---
Import the JSON format for the \"Security & Compliance | Reports\" export. Jfrog's Xray tool is an add-on to their Artifactory repository that does Software Composition Analysis, see https://www.jfrog.com/confluence/display/JFROG/JFrog+Xray for more information. \"Xray Unified\" refers to Xray Version 3.0 and later.

### Sample Scan Data
Sample JFrog XRay Unified scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/jfrog_xray_unified).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vulnerability ids
- file path
- component name
- component version
