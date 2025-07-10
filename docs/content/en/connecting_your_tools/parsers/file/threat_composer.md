---
title: "Threat Composer"
toc_hide: true
---
### File Types
This DefectDojo parser accepts JSON files from Threat Composer. The tool supports the [export](https://github.com/awslabs/threat-composer/tree/main?#features) of JSON report out of the browser local storage to a local file.

### Sample Scan Data
Sample scan data for testing purposes can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/threat_composer).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- description
