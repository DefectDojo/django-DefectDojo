---
title: "Trivy Operator"
toc_hide: true
---
JSON report of [trivy operator scanner](https://github.com/aquasecurity/trivy-operator).

To import the generated Vulnerability Reports, you can also use the [trivy-dojo-report-operator](https://github.com/telekom-mms/trivy-dojo-report-operator).

### Sample Scan Data
Sample Trivy Operator scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/trivy_operator).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- vulnerability ids
- description
