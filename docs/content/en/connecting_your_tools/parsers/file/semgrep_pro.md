---
title: "Semgrep Pro JSON Report"
toc_hide: true
---
Import Semgrep Pro findings in JSON format.

### Sample Scan Data
Sample Semgrep Pro JSON Report scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/semgrep_pro).

### Default Deduplication
By default, DefectDojo uses the `match_based_id` from Semgrep Pro for deduplication. If this is not available, it falls back to using a combination of:
- title
- file path
- line number

### Fields Mapped
The following fields are mapped from the Semgrep Pro JSON report:

#### Basic Information
- title: Mapped from `rule_name`
- severity: Mapped from Semgrep Pro severity levels (ERROR/HIGH → High, WARNING/MEDIUM → Medium, INFO/LOW → Low)
- file_path: Path to the affected file from `location.file_path`
- line: Line number from `location.line`
- unique_id_from_tool: Mapped from `match_based_id`

#### Status Fields
- active: Set to false if status is "fixed" or "removed"
- verified: Set to true if triage_state is not "untriaged"

#### Rich Content Fields
- description: Includes:
  - Rule message and details
  - CWE references
  - OWASP references
  - Categories
  - Triage information
- impact: Includes:
  - Vulnerability classes
  - Confidence level
  - Repository information
- mitigation: Includes:
  - Guidance summary
  - Detailed instructions
  - Auto-fix suggestions
  - Auto-triage information
  - Component details and risk level
- references: Includes:
  - Line of code URL
  - CWE references
  - OWASP references
  - External ticket information

#### Component Information
- component_name: Mapped from `assistant.component.tag`

#### Additional Fields
- static_finding: Always set to true
- dynamic_finding: Always set to false
- cwe: Extracted from first CWE reference if available
- date: Mapped from `created_at`