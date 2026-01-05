---
title: "Prowler Scan"
toc_hide: true
---
This parser imports Prowler Scan files in JSON and CSV format. The AWS, GCP, Azure, and Kubernetes could types are supported by this parser.

### Sample Scan Data
Sample Prowler scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/prowler).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- description
