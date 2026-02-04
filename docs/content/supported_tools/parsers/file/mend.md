---
title: "Mend Scan"
toc_hide: true
---

### File Types
Accepts a JSON file, generated from the Mend* Unified Agent.  

### Sample Scan Data / Unit Tests
Unit tests for Mend JSON files can be found at https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/mend

### Link To Tool
See documentation: https://docs.mend.io/bundle/unified_agent/page/example_of_a_unified_agent_json_report.html

*Formerly known as Whitesource.*

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- description
