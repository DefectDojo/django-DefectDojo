---
title: "Orca Security Alerts"
toc_hide: true
---

The [Orca Security](https://orca.security/) parser for DefectDojo supports imports from CSV and JSON formats. This document details the parsing of Orca Security alert exports into DefectDojo field mappings, unmapped fields, and location of each field's parsing code for easier troubleshooting and analysis.

## Supported File Types

The Orca Security parser accepts CSV and JSON file formats. To generate these files from Orca Security:

1. Log into the Orca Security console
2. Navigate to the Alerts page
3. Apply desired filters (scope, severity, status)
4. Click "Export" and select either CSV or JSON format
5. Save the exported file
6. Upload to DefectDojo using the "Orca Security Alerts" scan type

The parser auto-detects the format: files starting with `[` are treated as JSON, otherwise CSV.

## Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate Findings using the [unique_id_from_tool](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/) field, which is a SHA-256 hash of:

- CloudAccount.Name
- Inventory.Name
- Title

### Sample Scan Data

Sample Orca Security scans can be found in the [sample scan data folder](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/orca_security).

## Link To Tool

- [Orca Security](https://orca.security/)
- [Orca Security Documentation](https://docs.orcasecurity.io/)

## CSV Format

### Total Fields in CSV

- Total data fields: 12
- Total data fields parsed: 12
- Total data fields NOT parsed: 0

### CSV Format Field Mapping Details

<details>
<summary>Click to expand Field Mapping Table</summary>

| Source Field | DefectDojo Field | Parser File & Line # | Notes |
| ------------ | ---------------- | -------------------- | ----- |
| Title | title | csv_parser.py:24, helpers.py:51 | Truncated at 150 characters with "..." suffix |
| OrcaScore | severity | csv_parser.py:29, helpers.py:6 | Float mapped to severity string (see Severity Conversion) |
| OrcaScore | severity_justification | csv_parser.py:55, helpers.py:29 | Stored as "OrcaScore: X.X" |
| Category | description | csv_parser.py:25, helpers.py:67 | Included in structured markdown description |
| Inventory.Name | component_name | csv_parser.py:27, csv_parser.py:59 | Cloud resource name |
| CloudAccount.Name | description | csv_parser.py:28, helpers.py:73 | Included in description and used for dedup hash |
| Source | service | csv_parser.py:26, csv_parser.py:58 | Orca resource identifier populates service field |
| Source | description | csv_parser.py:26, helpers.py:69 | Also included in description |
| Status | active | csv_parser.py:30, csv_parser.py:63 | "open" = active, all else = inactive |
| CreatedAt | date | csv_parser.py:31, helpers.py:41 | ISO 8601 parsed to date object |
| LastSeen | description | csv_parser.py:32, helpers.py:81 | Included in description |
| Labels | tags | csv_parser.py:33, csv_parser.py:64-65 | JSON-encoded array parsed and stored as finding tags |
| CloudAccount.Name+Inventory.Name+Title | unique_id_from_tool | csv_parser.py:60, helpers.py:23 | SHA-256 hash for deduplication |

</details>

### Additional Finding Field Settings (CSV Format)

<details>
<summary>Click to expand Additional Settings Table</summary>

| Finding Field | Default Value | Parser File & Line # | Notes |
|---------------|---------------|----------------------|-------|
| static_finding | True | csv_parser.py:56 | CSPM scan data is static analysis |
| dynamic_finding | False | csv_parser.py:57 | Not a dynamic/runtime scan |
| active | Varies | csv_parser.py:63 | Based on Status field ("open" = True) |
| mitigation | Not set | — | Orca exports do not include remediation text |

</details>

## JSON Format

### Total Fields in JSON

- Total data fields: 10
- Total data fields parsed: 10
- Total data fields NOT parsed: 0

### JSON Format Field Mapping Details

<details>
<summary>Click to expand Field Mapping Table</summary>

| Source Field | DefectDojo Field | Parser File & Line # | Notes |
| ------------ | ---------------- | -------------------- | ----- |
| Title | title | json_parser.py:22, helpers.py:51 | Truncated at 150 characters with "..." suffix |
| OrcaScore | severity | json_parser.py:28, helpers.py:6 | Float mapped to severity string (see Severity Conversion) |
| OrcaScore | severity_justification | json_parser.py:49, helpers.py:29 | Stored as "OrcaScore: X.X" |
| Category | description | json_parser.py:23, helpers.py:67 | Included in structured markdown description |
| Inventory.Name | component_name | json_parser.py:34-35, json_parser.py:53 | Nested object, cloud resource name |
| CloudAccount.Name | description | json_parser.py:31-32, helpers.py:73 | Nested object, included in description and dedup hash |
| Source | service | json_parser.py:24, json_parser.py:52 | Orca resource identifier populates service field |
| Source | description | json_parser.py:24, helpers.py:69 | Also included in description |
| Status | active | json_parser.py:25, json_parser.py:57 | "open" = active, all else = inactive |
| CreatedAt | date | json_parser.py:26, helpers.py:41 | ISO 8601 parsed to date object |
| LastSeen | description | json_parser.py:27, helpers.py:81 | Included in description |
| Labels | tags | json_parser.py:29, json_parser.py:58-59 | Array of strings stored as finding tags |
| CloudAccount.Name+Inventory.Name+Title | unique_id_from_tool | json_parser.py:54, helpers.py:23 | SHA-256 hash for deduplication |

</details>

### Additional Finding Field Settings (JSON Format)

<details>
<summary>Click to expand Additional Settings Table</summary>

| Finding Field | Default Value | Parser File & Line # | Notes |
|---------------|---------------|----------------------|-------|
| static_finding | True | json_parser.py:50 | CSPM scan data is static analysis |
| dynamic_finding | False | json_parser.py:51 | Not a dynamic/runtime scan |
| active | Varies | json_parser.py:57 | Based on Status field ("open" = True) |
| mitigation | Not set | — | Orca exports do not include remediation text |

</details>

## Special Processing Notes

### Date Processing

The parser uses `dateutil.parser.parse()` to handle ISO 8601 date formats from Orca Security exports (helpers.py:41-48). The datetime is converted to a date object using `.date()`. Invalid or missing date strings return `None`.

### Severity Conversion

OrcaScore (float 0-10) is converted to DefectDojo severity levels (helpers.py:6-20):
- `0` or missing → Info
- `0.1 - 3.9` → Low
- `4.0 - 6.9` → Medium
- `7.0 - 8.9` → High
- `9.0 - 10.0` → Critical

The conversion uses `float()` with error handling — non-numeric values default to Info severity.

### Severity Justification

The OrcaScore is also stored in the `severity_justification` field as "OrcaScore: X.X" (helpers.py:29-38). This preserves the original numeric score for reference while the severity field contains the mapped categorical value.

### Description Construction

The parser builds a structured markdown description from all available alert fields (helpers.py:60-86). Each field is formatted as a bold label followed by its value, separated by double newlines. Fields with empty values are omitted. The description includes: Title, Category, Source, Inventory name, Cloud Account name, Orca Score, Status, Created date, Last Seen date, and Labels.

### Title Format

Finding titles use the alert's Title field directly (helpers.py:51-57). Titles longer than 150 characters are truncated with a "..." suffix. Alerts with no title receive the default "Orca Security Alert".

### Service Field

The Source field from Orca Security populates the DefectDojo `service` field (csv_parser.py:58, json_parser.py:52). This represents the cloud resource or service that generated the alert.

### Mitigation Construction

Orca Security CSV and JSON exports do not include remediation or mitigation text. The mitigation field is not populated by this parser.

### Deduplication

The `unique_id_from_tool` field is populated with a SHA-256 hex digest of the concatenation `CloudAccount.Name|Inventory.Name|Title` (helpers.py:23-26). This ensures consistent deduplication across both CSV and JSON imports — the same alert produces the same unique ID regardless of import format. Each row/item in the export becomes one Finding with no internal deduplication.

### Tags Handling

Labels from Orca Security are stored as finding tags using the `unsaved_tags` field (csv_parser.py:64-65, json_parser.py:58-59). This makes labels searchable and filterable in DefectDojo.

In CSV format, the Labels column contains a JSON-encoded array of strings (csv_parser.py:35-41). The parser uses `json.loads()` to parse this embedded JSON. If parsing fails, the raw string is used as a single tag. In JSON format, Labels is a native array of strings (json_parser.py:29).
