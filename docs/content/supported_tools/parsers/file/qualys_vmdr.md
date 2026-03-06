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

## Default Deduplication

The parser uses `DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL_OR_HASH_CODE`, which tries `unique_id_from_tool` (populated with the Qualys QID) first and falls back to hashcode deduplication.

**Hashcode fields:** `title`, `component_name`, `vuln_id_from_tool`

For more information, see [About Deduplication](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/).

### Sample Scan Data

Sample Qualys VMDR scans can be found in the [sample scan data folder](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/qualys_vmdr).

## Link To Tool

- [Qualys VMDR](https://www.qualys.com/apps/vulnerability-management-detection-response/)
- [Qualys Documentation](https://www.qualys.com/documentation/)

## QID Format (Primary Export)

### QID Format Field Mapping

<details>
<summary>Click to expand Field Mapping Table</summary>

| Source Field | DefectDojo Field | Notes |
| ------------ | ---------------- | ----- |
| Title | title | Truncated to 500 characters |
| Severity | severity | Mapped: 1=Info, 2=Low, 3=Medium, 4=High, 5=Critical |
| Severity | severity_justification | Preserved as "Qualys Severity: X" |
| QID | unique_id_from_tool | Native Qualys vulnerability identifier |
| QID | vuln_id_from_tool | Also used as vulnerability ID |
| First Detected | date | Parsed to date object |
| Status | active | True if "ACTIVE", False otherwise |
| Solution | mitigation | Remediation guidance |
| Threat | impact | Threat description |
| Asset Name | component_name | Asset/server name |
| Category | service | Vulnerability category |
| Asset IPV4 | unsaved_endpoints | Multiple endpoints if comma-separated |
| Asset IPV6 | unsaved_endpoints | Fallback if no IPv4 |
| Asset Tags | unsaved_tags | Split on comma |
| Results | description | Included in structured description |

</details>

### Additional Finding Settings (QID Format)

| Finding Field | Default Value | Notes |
|---------------|---------------|-------|
| static_finding | True | Vulnerability scan data |
| dynamic_finding | False | Not dynamic testing |

## CVE Format (Extended Export)

### CVE Format Field Mapping

<details>
<summary>Click to expand Field Mapping Table</summary>

| Source Field | DefectDojo Field | Notes |
| ------------ | ---------------- | ----- |
| CVE | vuln_id_from_tool | CVE identifier (e.g., CVE-2021-44228) |
| CVE | unsaved_vulnerability_ids | Also added for CVE tracking |
| CVE-Description | description | Prepended to structured description |
| CVSSv3.1 Base (nvd) | cvssv3_score | Numeric CVSS score |
| Title | title | Truncated to 500 characters |
| Severity | severity | Mapped: 1=Info, 2=Low, 3=Medium, 4=High, 5=Critical |
| Severity | severity_justification | Preserved as "Qualys Severity: X" |
| QID | unique_id_from_tool | Native Qualys vulnerability identifier |
| First Detected | date | Parsed to date object |
| Status | active | True if "ACTIVE", False otherwise |
| Solution | mitigation | Remediation guidance |
| Threat | impact | Threat description |
| Asset Name | component_name | Asset/server name |
| Category | service | Vulnerability category |
| Asset IPV4 | unsaved_endpoints | Multiple endpoints if comma-separated |
| Asset IPV6 | unsaved_endpoints | Fallback if no IPv4 |
| Asset Tags | unsaved_tags | Split on comma |
| Results | description | Included in structured description |

</details>

### Additional Finding Settings (CVE Format)

| Finding Field | Default Value | Notes |
|---------------|---------------|-------|
| static_finding | True | Vulnerability scan data |
| dynamic_finding | False | Not dynamic testing |

## Special Processing Notes

### Severity Conversion

Qualys severity levels (1-5 numeric scale) are converted to DefectDojo severity levels:
- `1` → Info
- `2` → Low
- `3` → Medium
- `4` → High
- `5` → Critical

The original Qualys severity is preserved in the severity_justification field as "Qualys Severity: X".

### Endpoint Handling

The parser creates Endpoint objects from IP addresses:
- Multiple IPv4 addresses (comma-separated) create multiple endpoints
- Falls back to IPv6 if no IPv4 address is present

### Format Detection

The parser automatically detects whether the import file is QID format or CVE format by examining the first column of the header row:
- If first column is "QID" → QID format parser is used
- If first column is "CVE" → CVE format parser is used
