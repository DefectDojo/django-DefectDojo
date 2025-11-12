---
title: "AWS Security Finding Format (ASFF)"
toc_hide: true
---

AWS Security Hub consumes, aggregates, organizes, and prioritizes findings from AWS security services and from the third-party product integrations. Security Hub processes these findings using a standard findings format called the AWS Security Finding Format (ASFF), which eliminates the need for time-consuming data conversion efforts. Then it correlates ingested findings across products to prioritize the most important ones.

Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html

Prowler tool can generate this format with option `-M json-asff`.

### Sample Scan Data
Sample AWS Security Finding Format (ASFF) scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/asff).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file path
- description
