---
title: "Semgrep Pro JSON Report"
toc_hide: true
---
Import Semgrep Pro findings in JSON format.

### Sample Scan Data
Sample Semgrep Pro JSON Report scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/semgrep_pro).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- file path
- line

### Fields Mapped
The following fields are mapped from the Semgrep Pro JSON report:

- title: The check_id from the finding
- severity: Mapped from Semgrep Pro severity levels
- description: Includes message, code snippet, impact, and confidence
- file_path: Path to the affected file
- line: Line number where the issue was found
- cwe: CWE number from metadata if available
- references: References from metadata if available
- mitigation: Fix information if available
- unique_id_from_tool: Finding ID if available
- component_name: Package name if available
- component_version: Package version if available