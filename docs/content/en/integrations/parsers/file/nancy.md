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
See Nancy on GitHub: https://github.com/sonatype-nexus-community/nancy
