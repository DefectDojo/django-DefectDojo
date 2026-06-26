---
title: "Orca Security Alerts"
toc_hide: true
---

The [Orca Security](https://orca.security/) parser for DefectDojo supports imports from CSV and JSON formats. This document details the parsing of Orca Security alert exports into DefectDojo field mappings and unmapped fields.

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

By default, DefectDojo identifies duplicate Findings using the [hashcode deduplication algorithm](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/) with the following fields:

- title
- component_name

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

| Source Field | DefectDojo Field | Notes |
| ------------ | ---------------- | ----- |
| Title | title | Truncated at 500 characters with "..." suffix |
| OrcaScore | severity | Float mapped to severity string (see Severity Conversion) |
| OrcaScore | severity_justification | Stored as "OrcaScore: X.X" |
| Category | description | Included in structured markdown description |
| Inventory.Name | component_name | Cloud resource name |
| CloudAccount.Name | description | Included in description and used for dedup hash |
| Source | service | Orca resource identifier populates service field |
| Source | description | Also included in description |
| Status | active | "open" = active, all else = inactive |
| CreatedAt | date | ISO 8601 parsed to date object |
| LastSeen | description | Included in description |
| Labels | tags | JSON-encoded array parsed and stored as finding tags |

</details>

### Additional Finding Field Settings (CSV Format)

<details>
<summary>Click to expand Additional Settings Table</summary>

| Finding Field | Default Value | Notes |
|---------------|---------------|-------|
| static_finding | True | CSPM scan data is static analysis |
| dynamic_finding | False | Not a dynamic/runtime scan |
| active | Varies | Based on Status field ("open" = True) |
| mitigation | Not set | Orca exports do not include remediation text |

</details>

## JSON Format

### Total Fields in JSON

- Total data fields: 10
- Total data fields parsed: 10
- Total data fields NOT parsed: 0

### JSON Format Field Mapping Details

<details>
<summary>Click to expand Field Mapping Table</summary>

| Source Field | DefectDojo Field | Notes |
| ------------ | ---------------- | ----- |
| Title | title | Truncated at 500 characters with "..." suffix |
| OrcaScore | severity | Float mapped to severity string (see Severity Conversion) |
| OrcaScore | severity_justification | Stored as "OrcaScore: X.X" |
| Category | description | Included in structured markdown description |
| Inventory.Name | component_name | Nested object, cloud resource name |
| CloudAccount.Name | description | Nested object, included in description and dedup hash |
| Source | service | Orca resource identifier populates service field |
| Source | description | Also included in description |
| Status | active | "open" = active, all else = inactive |
| CreatedAt | date | ISO 8601 parsed to date object |
| LastSeen | description | Included in description |
| Labels | tags | Array of strings stored as finding tags |

</details>

### Additional Finding Field Settings (JSON Format)

<details>
<summary>Click to expand Additional Settings Table</summary>

| Finding Field | Default Value | Notes |
|---------------|---------------|-------|
| static_finding | True | CSPM scan data is static analysis |
| dynamic_finding | False | Not a dynamic/runtime scan |
| active | Varies | Based on Status field ("open" = True) |
| mitigation | Not set | Orca exports do not include remediation text |

</details>

## Special Processing Notes

### Date Processing

The parser uses `dateutil.parser.parse()` to handle ISO 8601 date formats from Orca Security exports. The datetime is converted to a date object using `.date()`. Invalid or missing date strings return `None`.

### Severity Conversion

OrcaScore (float 0-10) is converted to DefectDojo severity levels:
- `0` or missing → Info
- `0.1 - 3.9` → Low
- `4.0 - 6.9` → Medium
- `7.0 - 8.9` → High
- `9.0 - 10.0` → Critical

The conversion uses `float()` with error handling — non-numeric values default to Info severity.

### Severity Justification

The OrcaScore is also stored in the `severity_justification` field as "OrcaScore: X.X". This preserves the original numeric score for reference while the severity field contains the mapped categorical value.

### Description Construction

The parser builds a structured markdown description from all available alert fields. Each field is formatted as a bold label followed by its value, separated by double newlines. Fields with empty values are omitted. The description includes: Title, Category, Source, Inventory name, Cloud Account name, Orca Score, Status, Created date, Last Seen date, and Labels.

### Title Format

Finding titles use the alert's Title field directly. Titles longer than 500 characters are truncated with a "..." suffix. Alerts with no title receive the default "Orca Security Alert".

### Service Field

The Source field from Orca Security populates the DefectDojo `service` field. This represents the cloud resource or service that generated the alert.

### Mitigation Construction

Orca Security CSV and JSON exports do not include remediation or mitigation text. The mitigation field is not populated by this parser.

### Deduplication

Deduplication uses the hashcode algorithm configured in `settings.dist.py` with the fields `title` and `component_name`. This ensures findings with the same alert title on the same resource are deduplicated across reimports. Each row/item in the export becomes one Finding with no internal deduplication.

### Tags Handling

Labels from Orca Security are stored as finding tags using the `unsaved_tags` field. This makes labels searchable and filterable in DefectDojo.

In CSV format, the Labels column contains a JSON-encoded array of strings. The parser uses `json.loads()` to parse this embedded JSON. If parsing fails, the raw string is used as a single tag. In JSON format, Labels is a native array of strings.
