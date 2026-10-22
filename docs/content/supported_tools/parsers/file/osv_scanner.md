---
title: "OSV Scanner"
toc_hide: true
---
Use [OSV-Scanner](https://github.com/google/osv-scanner) to find existing vulnerabilities affecting your project's dependencies.

### Vulnerability IDs
Each Finding gets the OSV advisory's `id` as its first vulnerability ID, followed by the advisory's `aliases`. An advisory keyed by a GHSA id usually lists its CVE only among the aliases.

### Sample Scan Data
Sample OSV Scanner output can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/osv_scanner).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](/triage_findings/finding_deduplication/about_deduplication/):

- title
- description
- severity
