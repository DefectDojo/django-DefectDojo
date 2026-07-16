---
title: "CargoAudit Scan"
toc_hide: true
---
Import JSON output of cargo-audit scan report <https://crates.io/crates/cargo-audit>

When an advisory includes a CVSS vector, the parser stores the CVSS v3.x or v4.0 vector and
its computed score on the Finding and derives the severity from it. Advisories without a
CVSS vector fall back to a severity of "High".

### Sample Scan Data
Sample CargoAudit Scan scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/cargo_audit).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](/en/working_with_findings/finding_deduplication/about_deduplication/):

- vulnerability ids
- severity
- component name
- component version
- vuln id from tool
