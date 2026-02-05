---
title: "Qualys VMDR"
toc_hide: true
---

The [Qualys VMDR](https://www.qualys.com/apps/vulnerability-management-detection-response/) parser for DefectDojo supports imports from CSV format. This parser handles both QID-centric and CVE-centric export variants from Qualys VMDR (Vulnerability Management, Detection, and Response).

## Supported File Types

The Qualys VMDR parser accepts CSV file format in two variants:

**QID Format:** Primary vulnerability identifier is the Qualys QID
**CVE Format:** Includes CVE identifiers and CVSS scores from NVD

To generate these files from Qualys VMDR:

1. Log into your Qualys VMDR console
2. Navigate to Vulnerabilities > Vulnerability Management
3. Select the assets or vulnerabilities to export
4. Click "Download" and select CSV format
5. Choose either QID-centric or CVE-centric export option
6. Upload the downloaded CSV file to DefectDojo

## Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- unique_id_from_tool (QID)

### Sample Scan Data

Sample Qualys VMDR scans can be found in the [sample scan data folder](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/qualys_vmdr).

## Link To Tool

- [Qualys VMDR](https://www.qualys.com/apps/vulnerability-management-detection-response/)
- [Qualys Documentation](https://www.qualys.com/documentation/)

## QID Format (Primary Export)

### Total Fields in QID CSV

- Total data fields: 41
- Total data fields parsed: 14
- Total data fields NOT parsed: 27

### QID Format Field Mapping Details

<details>
<summary>Click to expand Field Mapping Table</summary>

| Source Field | DefectDojo Field | Parser File | Notes |
| ------------ | ---------------- | ----------- | ----- |
| Title | title | qid_parser.py | Truncated to 150 characters |
| Severity | severity | qid_parser.py | Mapped: 1=Info, 2=Low, 3=Medium, 4=High, 5=Critical |
| Severity | severity_justification | qid_parser.py | Preserved as "Qualys Severity: X" |
| QID | unique_id_from_tool | qid_parser.py | Qualys vulnerability identifier for deduplication |
| First Detected | date | qid_parser.py | Parsed to date object |
| Status | active | qid_parser.py | True if "ACTIVE", False otherwise |
| Solution | mitigation | qid_parser.py | Remediation guidance |
| Threat | impact | qid_parser.py | Threat description |
| Asset Name | component_name | qid_parser.py | Asset/server name |
| Category | service | qid_parser.py | Vulnerability category |
| Asset IPV4 | unsaved_endpoints | qid_parser.py | Multiple endpoints if comma-separated |
| Asset IPV6 | unsaved_endpoints | qid_parser.py | Fallback if no IPv4 |
| Asset Tags | unsaved_tags | qid_parser.py | Split on comma |
| Results | description | qid_parser.py | Included in description |

</details>

### Additional Finding Field Settings (QID Format)

<details>
<summary>Click to expand Additional Settings Table</summary>

| Finding Field | Default Value | Parser File | Notes |
|---------------|---------------|-------------|-------|
| static_finding | True | qid_parser.py | Vulnerability scan data |
| dynamic_finding | False | qid_parser.py | Not dynamic testing |

</details>

## CVE Format (Extended Export)

### Total Fields in CVE CSV

- Total data fields: 41
- Total data fields parsed: 17
- Total data fields NOT parsed: 24

### CVE Format Field Mapping Details

<details>
<summary>Click to expand Field Mapping Table</summary>

| Source Field | DefectDojo Field | Parser File | Notes |
| ------------ | ---------------- | ----------- | ----- |
| CVE | vuln_id_from_tool | cve_parser.py | CVE identifier (e.g., CVE-2021-44228) |
| CVE | unsaved_vulnerability_ids | cve_parser.py | Also added to Vulnerability IDs for CVE tracking |
| CVE-Description | description | cve_parser.py | Prepended to description |
| CVSSv3.1 Base (nvd) | cvssv3_score | cve_parser.py | Numeric CVSS score |
| Title | title | cve_parser.py | Truncated to 150 characters |
| Severity | severity | cve_parser.py | Mapped: 1=Info, 2=Low, 3=Medium, 4=High, 5=Critical |
| Severity | severity_justification | cve_parser.py | Preserved as "Qualys Severity: X" |
| QID | unique_id_from_tool | cve_parser.py | Qualys vulnerability identifier for deduplication |
| First Detected | date | cve_parser.py | Parsed to date object |
| Status | active | cve_parser.py | True if "ACTIVE", False otherwise |
| Solution | mitigation | cve_parser.py | Remediation guidance |
| Threat | impact | cve_parser.py | Threat description |
| Asset Name | component_name | cve_parser.py | Asset/server name |
| Category | service | cve_parser.py | Vulnerability category |
| Asset IPV4 | unsaved_endpoints | cve_parser.py | Multiple endpoints if comma-separated |
| Asset IPV6 | unsaved_endpoints | cve_parser.py | Fallback if no IPv4 |
| Asset Tags | unsaved_tags | cve_parser.py | Split on comma |
| Results | description | cve_parser.py | Included in description |

</details>

### Additional Finding Field Settings (CVE Format)

<details>
<summary>Click to expand Additional Settings Table</summary>

| Finding Field | Default Value | Parser File | Notes |
|---------------|---------------|-------------|-------|
| static_finding | True | cve_parser.py | Vulnerability scan data |
| dynamic_finding | False | cve_parser.py | Not dynamic testing |

</details>

## Special Processing Notes

### Date Processing

The parser uses dateutil.parser to handle Qualys date formats (e.g., "Feb 03, 2026 07:00 AM"). The First Detected field is used for the finding date.

### Severity Conversion

Qualys severity levels (1-5 numeric scale) are converted to DefectDojo severity levels:
- `1` → Info
- `2` → Low
- `3` → Medium
- `4` → High
- `5` → Critical

The original Qualys severity is preserved in the severity_justification field as "Qualys Severity: X".

### Description Construction

The parser combines multiple fields to create a comprehensive markdown description:
- Title
- QID
- Category
- Threat
- RTI (Real-Time Intelligence)
- Operating System
- Results
- Last Detected

For CVE format, the description also includes:
- CVE identifier
- CVE Description from NVD

### Title Format

Finding titles use the vulnerability name directly from the Title field, truncated to 150 characters with "..." suffix if longer.

### Endpoint Handling

The parser creates Endpoint objects from IP addresses:
- Multiple IPv4 addresses (comma-separated) create multiple endpoints
- Falls back to IPv6 if no IPv4 address is present
- Each endpoint represents an affected asset

### Deduplication

DefectDojo uses the `unique_id_from_tool` field populated with the Qualys QID for deduplication. This ensures the same vulnerability type is deduplicated within an asset's scope.

### Tags Handling

Asset Tags are extracted and split by commas. Each tag is added to the finding's unsaved_tags list for categorization and filtering in DefectDojo.

### Format Detection

The parser automatically detects whether the import file is QID format or CVE format by examining the first column of the header row:
- If first column is "QID" → QID format parser is used
- If first column is "CVE" → CVE format parser is used
