---
title: "Solar Appscreener Scan"
toc_hide: true
---
Solar Appscreener report file can be imported in CSV format from Detailed_Results.csv

### Sample Scan Data
Sample Solar Appscreener Scan scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/solar_appscreener).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- file path
- line
- severity
