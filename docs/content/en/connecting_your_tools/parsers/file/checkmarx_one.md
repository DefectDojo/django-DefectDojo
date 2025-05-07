---
title: "Checkmarx One Scan"
toc_hide: true
---
Import JSON Checkmarx One scanner reports

# Checkmarx One JSON Parser Documentation

## Overview

The Checkmarx One parser for DefectDojo supports importing findings from Checkmarx One in JSON format. The parser handles three types of security findings including SAST (Static Application Security Testing), KICS (Kubernetes/Infrastructure as Code Security), and SCA (Software Composition Analysis) scan results, with specialized parsing logic for each type.

## Supported File Types

The Checkmarx One parser accepts JSON file format. To generate this file:

1. Log in to the Checkmarx One platform
2. Navigate to the Results view
3. Use the Export option to download findings in JSON format

The parser can handle several variations of the Checkmarx One JSON output format:
- Results in a top-level `results` array (primary format)
- Results in `vulnerabilities` array
- Results structured in separate sections (`scanResults`, `iacScanResults`, or `scaScanResults`)

## Standard Format JSON (Main Format)

### Total Fields in JSON

- Total data fields in Checkmarx JSON output: 24 core fields per finding (with nested fields)
- Total data fields parsed into DefectDojo finding: 17 fields
- Total data fields NOT parsed: 7 fields (some fields provide context but aren't directly mapped)

### Standard Format Field Mapping Details

| Data Field # | Checkmarx Data Field | DefectDojo Finding Field | Parser Line # | Notes |
|--------------|----------------------|--------------------------|---------------|-------|
| 1 | type | unsaved_tags | 361-368 | Added as a tag identifying the finding type (sast, kics, sca, etc.) |
| 2 | id | unique_id_from_tool | 342, 392, 409 | Primary unique identifier for the finding |
| 3 | similarityId | unique_id_from_tool | 342, 392, 409 | Used as fallback if id not present |
| 4 | status | - | 374 | Used for state determination but not directly mapped |
| 5 | state | active, verified, false_p | 534-546 | Maps Checkmarx states to DefectDojo fields through determine_state function |
| 6 | severity | severity | 343, 393, 410 | Converted to title case (e.g., "HIGH" → "High") |
| 7 | firstFoundAt | date | 351-354 | Used as finding date if USE_FIRST_SEEN setting is True |
| 8 | foundAt | date | 351-354 | Used as finding date if USE_FIRST_SEEN setting is False |
| 9 | description | description, title | 341, 391, 408 | Used for both description and title when available |
| 10 | descriptionHTML | - | - | Not mapped - HTML version of description is ignored |
| 11 | data.queryId | - | - | Used in KICS findings but not directly mapped |
| 12 | data.queryName | title (partial) | 341, 391 | Used as part of the title construction when needed |
| 13 | data.group/category | description (partial) | 120 | Added to description for KICS findings with "Category" prefix |
| 14 | data.line | line | 345 | Line number in file where vulnerability exists |
| 15 | data.fileName/filename | file_path | 344, 394 | Path to the vulnerable file |
| 16 | data.expectedValue | mitigation (partial) | 129-133 | Added to mitigation for KICS findings |
| 17 | data.value | mitigation (partial) | 129-133 | Added to mitigation for KICS findings |
| 18 | data.nodes[].fileName | description (partial) | 320-328 | Used in node snippets for SAST findings |
| 19 | data.nodes[].method | description (partial) | 320-328 | Used in node snippets for SAST findings |
| 20 | data.nodes[].line | description (partial) | 320-328 | Used in node snippets for SAST findings |
| 21 | data.nodes[].code | description (partial) | 320-328 | Used in node snippets for SAST findings |
| 22 | vulnerabilityDetails.cweId | cwe | 350, 353 | CWE ID number |
| 23 | vulnerabilityDetails.cvss | - | - | Not mapped directly |
| 24 | cveId | unsaved_vulnerability_ids | 414-415 | For SCA findings, mapped to vulnerability IDs list |

### Field Mapping Details

The parser contains three main methods for parsing different formats of Checkmarx One output:

1. `parse_results` (lines 337-370): Main entry point for parsing the standard format with a top-level `results` array
2. `parse_vulnerabilities` (lines 222-249): For parsing the format with a `vulnerabilities` array
3. `parse_vulnerabilities_from_scan_list` (lines 49-62): For parsing formats with separate sections by vulnerability type

Each vulnerability type has specialized parsing logic:

1. **SAST (Static Application Security Testing)** - `get_results_sast` (lines 389-404):
   - Focuses on code-level vulnerabilities
   - Uses file path from the first node
   - Tags findings with "sast"

2. **KICS (Kubernetes/IaC Security)** - `get_results_kics` (lines 406-423):
   - Infrastructure as Code findings
   - Extracts filename from data field
   - Tags findings with "kics"

3. **SCA (Software Composition Analysis)** - `get_results_sca` (lines 425-440):
   - Vulnerability in dependencies/packages
   - Handles CVE IDs when present
   - Tags findings with "sca" or "sca-container"

### Special Processing Notes

#### Status Conversion
- The `determine_state` function (lines 534-546) handles state conversion for all finding types
- Maps Checkmarx One states to DefectDojo fields:
  - "TO_VERIFY", "PROPOSED_NOT_EXPLOITABLE", "CONFIRMED", "URGENT" → active=True
  - "NOT_EXPLOITABLE", "CONFIRMED", "URGENT" → verified=True
  - "NOT_EXPLOITABLE" → false_p=True
  - All findings explicitly set duplicate=False and out_of_scope=False

#### Severity Conversion
- Severity values from Checkmarx One ("HIGH", "MEDIUM", "LOW", etc.) are converted to title case (lines 343, 393, 410)
- The parser takes the severity directly from the Checkmarx One finding and formats it to match DefectDojo's expected format
- No numerical conversion is performed, as Checkmarx One already provides categorical severity levels

#### Description Construction
- For SAST findings with nodes:
  - Function `get_node_snippet` (lines 320-328) formats code snippets
  - Includes file name, method name, line number, and code
  - Adds node snippets to description with separator
- For KICS findings:
  - Adds category information with "Category" prefix
  - Includes issue type information
  - Can include link to Checkmarx One for viewing the finding

#### Date Processing
- Uses a custom `_parse_date` method (lines 32-38) to handle multiple date formats
- Supports both string dates (parsed with dateutil.parser) and Timestamp objects with "seconds" field

#### Title Format
- SAST: Uses description text, or queryPath/queryName with underscores replaced by spaces
- KICS: Uses description or severity + queryName with underscores replaced
- SCA: Uses description or severity + queryName with underscores replaced
- When description is missing, title is constructed from severity and query name

#### Mitigation Construction
- For KICS findings:
  - Combines actual and expected values (lines 129-133)
  - Format: "**Actual Value**: {value}\n**Expected Value**: {expectedValue}\n"
- For SAST findings:
  - Uses general recommendations from CWE information when available

#### Deduplication
- Uses unique_id_from_tool based on finding "id" or "similarityId" as fallback
- Consistent across all finding types (SAST, KICS, SCA)
- No custom hash calculation is performed

#### Tags Handling
- Every finding gets tagged with its type (lines 368, 403, 419)
- Tags include: "sast", "kics", "sca", "sca-container"

#### Common Settings for All Findings
- All findings have static_finding=True
- SCA findings can have unsaved_vulnerability_ids populated with CVE IDs
- SAST findings include CWE information when available
- All findings have explicit settings for active, verified, false_p, duplicate, and out_of_scope

### Sample Scan Data
Sample Checkmarx One scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/checkmarx_one).

### Link To Tool
- [Checkmarx One](https://checkmarx.com/product/application-security-platform/)
- [Checkmarx One Documentation](https://checkmarx.com/resource/documents/en/34965-68516-checkmarx-one-documentation-portal.html)
