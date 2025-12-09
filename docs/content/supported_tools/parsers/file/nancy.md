---
title: "Nancy Scan"
toc_hide: true
---

Nancy output file (go list -json -deps ./... | nancy sleuth > nancy.json) can be imported in JSON format.


### File Types
This parser expects a JSON file.  

### Command Used To Generate Output
- \`go list -json -deps ./... | nancy sleuth > nancy.json\`

### Sample Scan Data
Sample Nancy scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/nancy).

### Link To Tool
See Nancy on [Github](https://github.com/sonatype-nexus-community/nancy)

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- vuln id from tool
