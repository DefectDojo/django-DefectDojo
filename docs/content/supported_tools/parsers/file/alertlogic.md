---
title: "Alert Logic"
toc_hide: true
---

The [Alert Logic](https://www.alertlogic.com/) parser for DefectDojo supports imports from CSV format. This document details the parsing of Alert Logic vulnerability scan exports into DefectDojo field mappings, unmapped fields, and transformation notes for easier troubleshooting and analysis.

## Supported File Types

The Alert Logic parser accepts CSV file format. To generate this file from Alert Logic:

1. Log into the Alert Logic console
2. Navigate to **Validate → Vulnerabilities** (or the equivalent vulnerability listing view)
3. Apply the filters you want included in the export
4. Export the filtered vulnerability list as CSV
5. Save the file with a `.csv` extension
6. Upload to DefectDojo using the "Alert Logic Scan" scan type

The parser handles UTF-8 with byte-order mark (BOM) and multi-line quoted fields commonly present in Description, Evidence, and Resolution columns.

## Default Deduplication Hashcode Fields

Alert Logic provides a stable native vulnerability identifier in the `Vulnerability ID` column. DefectDojo uses it as `unique_id_from_tool` with hashcode fields as a fallback:

- title
- component_name
- vuln_id_from_tool

### Sample Scan Data

Sample Alert Logic scans can be found in the [sample scan data folder](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/alertlogic).

## Link To Tool

- [Alert Logic](https://www.alertlogic.com/)
- [Alert Logic Documentation](https://docs.alertlogic.com/)

## CSV Format

### Total Fields in CSV

- Total data fields: 26
- Total data fields parsed: 26
- Total data fields NOT parsed: 0

### CSV Format Field Mapping Details

<details>
<summary>Click to expand Field Mapping Table</summary>

| Source Field            | DefectDojo Field            | Notes                                                                          |
| ----------------------- | --------------------------- | ------------------------------------------------------------------------------ |
| Vulnerability           | title                       | Truncated to 500 characters with "..." suffix if longer                        |
| Severity                | severity                    | Direct one-to-one mapping (Info / Low / Medium / High / Critical)              |
| CVSS Score              | cvssv3_score                | Parsed as float; empty values produce no score                                 |
| Asset Name              | component_name              | The affected host or service from the scan                                     |
| IP Address              | unsaved_endpoints           | Comma-separated IPv4 / IPv6 list; each value becomes a separate endpoint       |
| Protocol/Port           | unsaved_endpoints           | Parsed as `PROTOCOL/PORT`; a port of 0 is omitted                              |
| CVE                     | unsaved_vulnerability_ids   | Single CVE identifier when present                                             |
| Resolution              | mitigation                  | Direct copy, including multi-line content                                      |
| Vulnerability ID        | unique_id_from_tool         | Alert Logic's stable native vulnerability identifier (used for deduplication)  |
| Description             | description                 | Included in structured description block                                       |
| Evidence                | description                 | Included in structured description block                                       |
| Operating System        | description                 | Included in structured description block (CPE strings preserved)               |
| Vulnerability Span ID   | description                 | Included in structured description block                                       |
| Vulnerability Key       | description                 | Included in structured description block                                       |
| Asset Key               | description                 | Included in structured description block                                       |
| Asset Type              | description                 | Included in structured description block                                       |
| Service                 | description                 | Included in structured description block                                       |
| Category                | description                 | Included in structured description block                                       |
| VPC/Network             | description                 | Included in structured description block                                       |
| Deployment Name         | description                 | Included in structured description block                                       |
| Customer Account        | description                 | Included in structured description block                                       |
| First Seen              | description                 | Included in structured description block                                       |
| Last Scanned            | description                 | Included in structured description block                                       |
| Published Date          | description                 | Included in structured description block                                       |
| Age (days)              | description                 | Included in structured description block                                       |
| CISA Known Exploited    | description, unsaved_tags   | Added as `cisa-known-exploited` tag when value is "Yes"                        |

</details>

### Additional Finding Field Settings (CSV Format)

<details>
<summary>Click to expand Additional Settings Table</summary>

| Finding Field    | Default Value | Notes                                                       |
| ---------------- | ------------- | ----------------------------------------------------------- |
| static_finding   | True          | Alert Logic is an infrastructure vulnerability scanner      |
| dynamic_finding  | False         | Alert Logic is an infrastructure vulnerability scanner      |
| active           | True          | Alert Logic exports do not carry a mitigation status column |

</details>

## Special Processing Notes

### Severity Conversion

Alert Logic uses a five-level severity scale that aligns one-to-one with DefectDojo severity levels:

- `Critical` → Critical
- `High` → High
- `Medium` → Medium
- `Low` → Low
- `Info` → Info

Any unrecognized severity value defaults to Info.

### Title Format

Finding titles are derived from the "Vulnerability" column. Titles longer than 500 characters are truncated to 497 characters with a "..." suffix appended. Shorter titles are used as-is without modification.

### Description Construction

The parser constructs a structured markdown description containing all relevant CSV fields not already mapped to dedicated Finding columns. Each field is rendered as `**Label:** value` with blank lines between entries. Fields are included only when they contain a non-empty value, so the description stays tight for sparsely populated rows.

### Endpoint Construction

The "IP Address" column may contain one or more comma-separated IP addresses, mixing IPv4 and IPv6 (for example: `198.51.100.30, fe80::250:56ff:fe96:b97`). Each address becomes a separate endpoint. The "Protocol/Port" column is parsed as `PROTOCOL/PORT` (e.g., `TCP/443`); when the port is `0` the value is treated as "no specific port" and omitted from the endpoint. All endpoints are validated via `endpoint.clean()` before being attached to the finding.

### Deduplication

Alert Logic exports include a stable per-vulnerability identifier in the "Vulnerability ID" column. DefectDojo uses this as `unique_id_from_tool` and the deduplication algorithm `DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL_OR_HASH_CODE`. When the ID is missing (some scan exports omit it for non-vulnerability findings), DefectDojo falls back to the hashcode algorithm using `title`, `component_name`, and `vuln_id_from_tool` (the CVE) as the stable fields.

### CVE Handling

The "CVE" column carries a single CVE identifier or is empty. When present it is attached to the finding via `unsaved_vulnerability_ids`; when absent no CVE is set.

### CISA Known Exploited Tagging

When the "CISA Known Exploited" column equals "Yes", the finding receives a `cisa-known-exploited` tag. This makes it straightforward to filter, route, or escalate findings already known to be exploited in the wild.

### BOM and Multi-Line Field Handling

Alert Logic exports start with a UTF-8 byte-order mark (`\xef\xbb\xbf`). The parser uses `utf-8-sig` decoding to strip the BOM transparently. Description, Evidence, and Resolution columns frequently contain multi-line content (separated by `\r\n` inside the quoted field); these newlines are preserved in the resulting `description` and `mitigation` Finding fields.
