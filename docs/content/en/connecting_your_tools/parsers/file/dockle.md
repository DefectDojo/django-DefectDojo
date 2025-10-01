---
title: "Dockle Report"
toc_hide: true
---
Import JSON container image linter reports
<https://github.com/goodwithtech/dockle>

### Sample Scan Data
Sample Dockle Report scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/dockle).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- description
- vuln id from tool
