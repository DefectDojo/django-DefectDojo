---
title: "IriusRisk Threats Scan"
toc_hide: true
---

The [IriusRisk](https://www.iriusrisk.com/) parser for DefectDojo supports imports from CSV format. This document details the parsing of IriusRisk threat model CSV exports into DefectDojo field mappings, unmapped fields, and location of each field's parsing code for easier troubleshooting and analysis.

## Supported File Types

The IriusRisk parser accepts CSV file format. To generate this file from IriusRisk:

1. Log into your IriusRisk console
2. Navigate to the project containing your threat model
3. Export the threats as CSV
4. Save the file with a `.csv` extension
5. Upload to DefectDojo using the "IriusRisk Threats Scan" scan type

## Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file_path
- description

The parser also populates `unique_id_from_tool` with a SHA-256 hash of the Component, Threat, and Risk Response fields, providing an additional layer of deduplication across reimports.

### Sample Scan Data

Sample IriusRisk scans can be found in the [sample scan data folder](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/iriusrisk).

## Link To Tool

- [IriusRisk](https://www.iriusrisk.com/)
- [IriusRisk Documentation](https://support.iriusrisk.com/)

## CSV Format (Threat Model Export)

### Total Fields in CSV

- Total data fields: 14
- Total data fields parsed: 14
- Total data fields NOT parsed: 0

### CSV Format Field Mapping Details

<details>
<summary>Click to expand Field Mapping Table</summary>

| Source Field             | DefectDojo Field     | Parser Line # | Notes                                                                 |
| ------------------------ | -------------------- | ------------- | --------------------------------------------------------------------- |
| Threat                   | title                | 51            | Truncated to 150 characters with "..." suffix if longer               |
| Current Risk             | severity             | 53            | Mapped from IriusRisk risk levels to DefectDojo severity levels       |
| Component                | component_name       | 95            | The affected asset or component from the threat model                 |
| Threat                   | description          | 57            | Full threat text included as first line of structured description     |
| Component                | description          | 58            | Included in structured description block                              |
| Use case                 | description          | 59            | Threat category included in structured description                    |
| Source                   | description          | 60            | Origin of the threat included in structured description               |
| Inherent Risk            | description          | 61            | Pre-control risk level included in structured description             |
| Current Risk             | description          | 62            | Current risk level included in structured description                 |
| Projected Risk           | description          | 63            | Post-mitigation risk level included in structured description         |
| Countermeasure progress  | description          | 64            | Percentage complete included in structured description                |
| Weakness tests           | description          | 65            | Test status included in structured description                        |
| Countermeasure tests     | description          | 66            | Test status included in structured description                        |
| Owner                    | description          | 68-69         | Conditionally appended to description only when present               |
| STRIDE-LM               | description          | 70-71         | Conditionally appended to description only when present               |
| Risk Response            | mitigation           | 94            | Mitigation status percentages from IriusRisk                          |
| MITRE reference          | cwe                  | 82-85         | When value matches CWE-NNN pattern, integer is extracted to cwe field |
| MITRE reference          | references           | 86-87         | When value does not match CWE pattern, stored as references           |
| Component + Threat + Risk Response | unique_id_from_tool | 74-77 | SHA-256 hash used for deduplication across reimports                  |

</details>

### Additional Finding Field Settings (CSV Format)

<details>
<summary>Click to expand Additional Settings Table</summary>

| Finding Field    | Default Value                    | Parser Line # | Notes                                                       |
| ---------------- | -------------------------------- | ------------- | ----------------------------------------------------------- |
| static_finding   | False                            | 97            | Threat model data is neither static nor dynamic analysis    |
| dynamic_finding  | False                            | 98            | Threat model data is neither static nor dynamic analysis    |
| active           | True (False when "Very low")     | 96            | Set to False when Current Risk is "Very low" (fully mitigated) |
| unique_id_from_tool | SHA-256 hash                  | 99            | Hash of Component, Threat, and Risk Response                |

</details>

## Special Processing Notes

### Status Conversion

IriusRisk uses a five-level risk scale that is mapped to DefectDojo severity levels (lines 8-14):

- `Critical` → Critical
- `High` → High
- `Medium` → Medium
- `Low` → Low
- `Very low` → Info

Any unrecognized risk value defaults to Info (line 53). The mapping uses the "Current Risk" column, which reflects the risk level accounting for existing controls and represents the most accurate current exposure.

### Title Format

Finding titles are derived from the "Threat" column (line 51). Threat descriptions longer than 150 characters are truncated to 147 characters with a "..." suffix appended. Shorter threat texts are used as-is without modification.

### Description Construction

The parser constructs a structured markdown description containing all relevant CSV fields (lines 56-72):

1. Full threat text (untruncated, regardless of title truncation)
2. Component name
3. Use case (threat category, e.g., "Elevation of Privilege", "Networking")
4. Source (e.g., "Created by Rules Engine")
5. Inherent Risk (pre-control risk level)
6. Current Risk (risk with existing controls)
7. Projected Risk (risk after planned mitigations)
8. Countermeasure Progress (percentage complete)
9. Weakness Tests (test status)
10. Countermeasure Tests (test status)
11. Owner (conditionally included only when the field contains a value)
12. STRIDE-LM (conditionally included only when the field contains a value)

Each field is formatted as a bold markdown label followed by the value, with fields separated by newlines.

### MITRE Reference / CWE Extraction

The parser reads the "MITRE reference" column (lines 79-87) and applies conditional mapping:

- If the value matches the pattern `CWE-NNN` (e.g., "CWE-284"), the integer portion is extracted and set on the finding's `cwe` field.
- If the value is present but does not match the CWE pattern (e.g., "T1059" for a MITRE ATT&CK technique), the full value is stored in the finding's `references` field.
- If the column is empty, neither field is set.

### Mitigation Construction

The mitigation field is populated directly from the "Risk Response" column (line 94), which contains the IriusRisk mitigation status in the format: "Planned mitigation: X%. Mitigated: Y%. Unmitigated: Z%." This preserves the original IriusRisk mitigation tracking percentages.

### Active/Inactive Logic

Findings are set to active by default (line 96). When the "Current Risk" value is "Very low", the finding is set to inactive, as this indicates the threat has been fully mitigated through implemented countermeasures.

### Deduplication

The parser generates a `unique_id_from_tool` by computing a SHA-256 hash of the Component, Threat, and Risk Response fields concatenated with pipe delimiters (lines 74-77). This ensures that each distinct combination of component, threat, and mitigation state produces a unique identifier. On reimport, findings with matching unique IDs are recognized as the same finding rather than being duplicated.

### Duplicate Rows in Source Data

IriusRisk CSV exports can contain multiple rows with the same Component and Threat but different Risk Response values. These represent distinct countermeasure paths for the same threat. Each row is imported as a separate finding, distinguished by its unique ID which incorporates the Risk Response field.
