---
title: "Strix Scan"
toc_hide: true
---

The [Strix](https://github.com/usestrix/strix) parser for DefectDojo supports imports from the JSON report of a Strix security run. This document details how Strix findings are mapped into DefectDojo Findings, which fields are parsed, and the deduplication behavior.

## Supported File Types

The Strix parser accepts JSON files in the format of the `vulnerabilities.json` report produced by a Strix run.

To import Strix results into DefectDojo:

1. Run Strix against the target codebase
2. Export or copy the resulting `vulnerabilities.json` report
3. Upload the file to DefectDojo using the "Strix Scan" scan type

The report is a JSON array with one object per finding. A wrapped shape (`{"vulnerabilities": [...]}`) is also accepted for forward compatibility. Every field is optional: the set of keys varies by `finding_class` (code findings carry PoC and CVSS data, dependency findings carry package metadata), so missing fields are left unset on the Finding rather than filled with placeholders; the one exception is `title`, which falls back to the report id (or a generic name) because a Finding without a title cannot be saved. A report that is not a JSON array (or a wrapped one) is rejected with an error instead of silently importing zero findings; a legitimately empty array imports zero findings.

## Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate Findings using these [hashcode fields](/triage_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- file_path
- component_name
- vulnerability ids

Strix numbers findings per run (`vuln-0001`, `vuln-0002` and so on), so the same id can point at different issues in different runs and cannot drive deduplication; the report `id` is kept in `vuln_id_from_tool` for reference only. The fields above stay the same between runs of an unchanged codebase; `file_path`, `component_name` and `vulnerability_ids` are each populated only by some finding classes and empty on the others, so every finding class deduplicates on the subset it actually carries.

### Sample Scan Data

Sample Strix scans can be found in the [sample scan data folder](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/strix).

## Link To Tool

- [Strix](https://github.com/usestrix/strix)

## JSON Format

### Total Fields in JSON

- Total data fields: 30
- Total data fields parsed into dedicated Finding fields, the structured description, or the mitigation: 28
- Remaining fields (`agent_id`, `agent_name`) identify the Strix agent that produced the finding and are not mapped

### JSON Format Field Mapping Details

<details>
<summary>Click to expand Field Mapping Table</summary>

| Source Field           | DefectDojo Field          | Notes                                                                    |
| ---------------------- | ------------------------- | ------------------------------------------------------------------------ |
| title                  | title                     | Finding title                                                            |
| severity               | severity                  | Mapped to DefectDojo severity levels; defaults to Info if unrecognized   |
| description            | description               | First section of the structured description                               |
| impact                 | impact                    | Finding impact                                                           |
| target                 | description               | Included as a "**Target:**" line in the description                      |
| confidence             | description               | Included as a "**Confidence:**" line in the description                  |
| cvss                   | cvssv3_score              | Numeric CVSS score, set when the value is a number                       |
| cvss_breakdown         | cvssv3                    | Assembled into a CVSS:3.1 vector string, parsed into the `cvssv3` field, and shown next to the score in the description |
| cwe                    | cwe                       | `CWE-<number>` extracted from the string                                 |
| cve                    | unsaved_vulnerability_ids | Set as the finding's vulnerability reference                              |
| id                     | vuln_id_from_tool         | Strix finding identifier, kept verbatim for reference; not used for deduplication |
| timestamp              | date                      | Parsed finding date                                                      |
| finding_class          | static_finding / dynamic_finding | `dynamic` marks a dynamic finding; anything else marks a static finding |
| remediation_steps      | mitigation                | First part of the mitigation                                             |
| fix_effort             | mitigation                | Included as a "**Fix effort:**" line in the mitigation                    |
| fix_pr_body            | fix_available             | Contributes (with remediation_steps) to a non-null mitigation and fix_available |
| poc_description        | steps_to_reproduce        | Reproduction steps                                                      |
| poc_script_code        | steps_to_reproduce        | PoC script, appended after the steps                                     |
| technical_analysis     | description               | "## Technical analysis" description section                              |
| evidence               | description               | "## Evidence" description section                                        |
| assumptions            | description               | "## Assumptions" description section                                     |
| counterevidence        | description               | "## Counter-evidence" description section                                |
| severity_change_conditions | description            | "## Conditions that would change severity" description section           |
| fix_verification       | not mapped                | Verification note from the fix run; not currently mapped                  |
| code_locations         | file_path / line          | First code location anchors the finding's file and start line             |
| dependency_metadata.package_name | component_name    | Dependency finding component name                                       |
| dependency_metadata.installed_version | component_version | Dependency finding component version                                     |
| dependency_metadata (other keys) | not mapped       | Advisory CVSS, ecosystem, manifest path, and reachability metadata are not currently mapped |
| agent_id / agent_name   | not mapped                | Strix agent identifiers                                                  |

</details>

### Additional Finding Field Settings (JSON Format)

| Finding Field   | Default Value | Notes                                                          |
| --------------- | ------------- | -------------------------------------------------------------- |
| active          | True          | Standard default for imported findings                          |
| verified        | False         | Findings import as unverified until a tester verifies them              |
| static_finding  | True          | Unless `finding_class` is `dynamic`                              |
| dynamic_finding | True          | Only when `finding_class` is `dynamic`                          |
| fix_available  | True          | When the report carries remediation_steps or a fix PR body      |

## Special Processing Notes

### Severity Mapping

- `critical` → Critical
- `high` → High
- `medium` → Medium
- `low` → Low
- `info` / `informational` → Info

Any unrecognized or missing value defaults to Info.

### Description Construction

The description is assembled from the parts the report actually carries: the base description, then optional "**Target:**", "**Confidence:**", and "**CVSS:**" lines, followed by the analysis sections ("Technical analysis", "Evidence", "Assumptions", "Counter-evidence", "Conditions that would change severity") rendered as markdown headings. Sections without data are omitted, so a minimal finding gets a short description and a full report gets the complete analysis.
