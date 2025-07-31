---
title: "Coverity API"
toc_hide: true
---
Export Coverity API view data in JSON format (`/api/viewContents/issues` endpoint).

Currently these columns are mandatory:
 * `displayType` (`Type` in the UI)
 * `displayImpact` (`Impact` in the UI)
 * `status` (`Status` in the UI)
 * `firstDetected` (`First Detected` in the UI)

Other supported attributes: `cwe`, `displayFile`, `occurrenceCount` and `firstDetected`

### Sample Scan Data
Sample Coverity API scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/coverity_api).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file path
- description
