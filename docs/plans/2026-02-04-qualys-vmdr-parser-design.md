# Qualys VMDR Parser Design

**Date:** 2026-02-04
**Author:** Tracy Walker
**Status:** Draft

## Overview

This document describes the design for a DefectDojo parser that imports Qualys VMDR (Vulnerability Management, Detection, and Response) scan exports. The parser supports two CSV export variants: QID-centric and CVE-centric formats.

## Tool Information

- **Tool Name:** Qualys VMDR
- **Tool URL:** https://www.qualys.com/apps/vulnerability-management-detection-response/
- **Scan Type Name:** "Qualys VMDR"
- **Parser Directory:** `dojo/tools/qualys_vmdr/`
- **Parser Class:** `QualysVMDRParser`
- **Supported Formats:** CSV (two variants)

## File Structure

```
dojo/tools/qualys_vmdr/
├── __init__.py        # Empty (required for Python package)
├── parser.py          # Main entry point, format dispatcher
├── qid_parser.py      # QID-centric CSV parsing
├── cve_parser.py      # CVE-centric CSV parsing
└── helpers.py         # Shared utilities

unittests/scans/qualys_vmdr/
├── no_vuln_qid.csv    # QID format, headers only
├── one_vuln_qid.csv   # QID format, single finding
├── many_vulns_qid.csv # QID format, multiple findings
├── no_vuln_cve.csv    # CVE format, headers only
├── one_vuln_cve.csv   # CVE format, single finding
└── many_vulns_cve.csv # CVE format, multiple findings

unittests/tools/
└── test_qualys_vmdr_parser.py

docs/content/supported_tools/parsers/file/
└── qualys_vmdr.md
```

## CSV Format Details

### Common Structure

Both formats share the same structure:
- **Lines 1-3:** Report metadata (report name, company info, user info)
- **Line 4:** CSV column headers
- **Lines 5+:** Data rows

### Format Detection

Detect format by checking the first column header on line 4:
- Starts with `"QID,` → QID format
- Starts with `"CVE,` → CVE format

### QID Format Columns (41 total)

```
QID, Title, Severity, KB Severity, Type Detected, Last Detected,
First Detected, Protocol, Port, Status, Asset Id, Asset Name,
Asset IPV4, Asset IPV6, Solution, Asset Tags, Disabled, Ignored,
QDS, QDS Severity, Detection AGE, Published Date, Patch Released,
Category, RTI, Operating System, Last Fixed, Last Reopened,
Times Detected, Threat, Vuln Patchable, Asset Critical Score,
TruRisk Score, Vulnerability Tags, Results, Deep Scan Result,
Detection Source, MITRE ATT&CK TACTIC ID, MITRE ATT&CK TACTIC NAME,
MITRE ATT&CK TECHNIQUE ID, MITRE ATT&CK TECHNIQUE NAME
```

### CVE Format Columns (41 total)

```
CVE, CVE-Description, CVSSv2 Base (nvd), CVSSv3.1 Base (nvd), QID,
Title, Severity, KB Severity, Type Detected, Last Detected,
First Detected, Protocol, Port, Status, Asset Id, Asset Name,
Asset IPV4, Asset IPV6, Solution, Asset Tags, Disabled, Ignored,
QVS Score, Detection AGE, Published Date, Patch Released, Category,
CVSS Rating Labels, RTI, Operating System, Last Fixed, Last Reopened,
Times Detected, Threat, Vuln Patchable, Asset Critical Score,
TruRisk Score, Vulnerability Tags, Results, Deep Scan Result,
Detection Source
```

### CSV Parsing Challenges

- **Multi-line fields:** Results field contains embedded newlines
- **Quote escaping:** Uses doubled double-quotes (`""`)
- **Metadata header:** Must skip first 3 lines before CSV parsing

## Field Mappings

### QID Format → Finding Fields

| Qualys Field | Finding Field | Notes |
|--------------|---------------|-------|
| Title | `title` | Truncated to 150 chars with "..." |
| Severity | `severity` | 1=Info, 2=Low, 3=Medium, 4=High, 5=Critical |
| Severity | `severity_justification` | "Qualys Severity: X" |
| QID | `unique_id_from_tool` | Qualys internal ID for deduplication |
| First Detected | `date` | Parsed to date object |
| Status | `active` | True if "ACTIVE", else False |
| Solution | `mitigation` | As-is |
| Threat | `impact` | As-is |
| Asset Name | `component_name` | The specific asset |
| Category | `service` | e.g., "Internet Explorer" |
| Asset IPV4 (or IPV6) | `unsaved_endpoints` | Multiple endpoints if comma-separated |
| Asset Tags | `unsaved_tags` | Split on comma |
| — | `static_finding` | True |
| — | `dynamic_finding` | False |

### CVE Format Additional Mappings

| Qualys Field | Finding Field | Notes |
|--------------|---------------|-------|
| CVE | `vuln_id_from_tool` | Non-unique technical ID (e.g., "CVE-2015-6149") |
| QID | `unique_id_from_tool` | Same as QID format |
| CVE-Description | Added to `description` | Prepended to description |
| CVSSv3.1 Base (nvd) | `cvssv3_score` | Numeric score (float) |

### Severity Mapping

| Qualys Severity | DefectDojo Severity |
|-----------------|---------------------|
| 1 | Info |
| 2 | Low |
| 3 | Medium |
| 4 | High |
| 5 | Critical |
| Invalid/missing | Info |

### Description Construction

Markdown-formatted description includes:
- Title
- QID
- Category
- Threat
- RTI (Real-Time Intelligence indicators)
- Operating System
- Results
- Last Detected

For CVE format, also includes:
- CVE identifier
- CVE-Description

### Endpoint Handling

- Parse Asset IPV4 field, splitting on comma for multiple IPs
- Create one Endpoint object per IP address
- Fall back to Asset IPV6 if Asset IPV4 is empty
- Return empty list if neither field has valid IPs

### Deduplication Strategy

- `unique_id_from_tool` = QID value directly
- DefectDojo handles asset-level scoping internally
- Same vulnerability on different assets creates separate findings

## helpers.py Functions

```python
def map_qualys_severity(severity_value):
    """Map Qualys severity (1-5) to DefectDojo severity string."""

def build_severity_justification(severity_value):
    """Return 'Qualys Severity: X' to preserve original score."""

def parse_qualys_date(date_string):
    """Parse Qualys date format: 'Feb 03, 2026 07:00 AM'."""

def truncate_title(title, max_length=150):
    """Truncate title with '...' suffix if needed."""

def build_description(row, format_type):
    """Build markdown description from CSV row fields."""

def parse_endpoints(ipv4_field, ipv6_field):
    """Parse IP addresses and return list of Endpoint objects."""

def parse_tags(tags_field):
    """Split comma-separated tags into list."""
```

## Parser Flow

### Main Dispatcher (parser.py)

1. Read content, decode if bytes
2. Split into lines
3. Skip lines 0-2 (metadata headers)
4. Check line 3 for format indicator
5. Delegate to QIDParser or CVEParser
6. Return list of Finding objects

### Format-Specific Parsers

1. Skip first 3 lines (metadata)
2. Use `csv.DictReader` on remaining content
3. For each row, create Finding object with mapped fields
4. Return findings list

## Test Strategy

### Test Files

| File | Description |
|------|-------------|
| `no_vuln_qid.csv` | 3 metadata lines + header row, no data rows |
| `one_vuln_qid.csv` | Single finding, severity 5 (Critical) |
| `many_vulns_qid.csv` | 5 findings with severities 1-5, varied statuses |
| `no_vuln_cve.csv` | 3 metadata lines + header row, no data rows |
| `one_vuln_cve.csv` | Single finding with CVE and CVSS score |
| `many_vulns_cve.csv` | 5 findings with varied CVEs and CVSS scores |

### Test Cases

- Format detection (QID vs CVE)
- Empty files (no findings)
- Single finding parsing
- Multiple findings parsing
- Field mapping verification (title, severity, dates, etc.)
- Endpoint parsing (single IP, multiple IPs, IPv6 fallback)
- Tags parsing
- Edge cases (multiline fields, missing fields, invalid values)

## Reference Implementation

The Orca Security parser (`dojo/tools/orca_security/`) serves as the architectural reference:
- Multi-format dispatcher pattern
- Shared helpers.py module
- Format-specific parser files
- Consistent field mapping approach

## Documentation

Parser documentation follows the enhanced format structure defined in `docs/plans/enhanced-format-structure.md`:
- Field mapping tables with parser line numbers
- Special processing notes for each transformation
- Deduplication strategy explanation
- Export instructions for users

## Implementation Checklist

- [ ] Create `dojo/tools/qualys_vmdr/__init__.py`
- [ ] Create `dojo/tools/qualys_vmdr/helpers.py`
- [ ] Create `dojo/tools/qualys_vmdr/qid_parser.py`
- [ ] Create `dojo/tools/qualys_vmdr/cve_parser.py`
- [ ] Create `dojo/tools/qualys_vmdr/parser.py`
- [ ] Create test scan files in `unittests/scans/qualys_vmdr/`
- [ ] Create `unittests/tools/test_qualys_vmdr_parser.py`
- [ ] Create `docs/content/supported_tools/parsers/file/qualys_vmdr.md`
- [ ] Run ruff linter
- [ ] Run unit tests
- [ ] Test in DefectDojo UI
- [ ] Create PR to upstream dev branch
