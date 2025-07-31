---
title: "Blackduck Hub"
toc_hide: true
---
2 options:

* Import the zip file as can be created by Blackduck export.
The zip file must contain the security.csv and files.csv in order to
produce findings that bear file locations information.
* Import a single security.csv file. Findings will not have any file location
information.

### Sample Scan Data
Sample Blackduck Hub scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/blackduck).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- vulnerability ids
- component name
- component version
