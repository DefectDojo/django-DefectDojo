---
title: "Nexpose XML 2.0 (Rapid7)"
toc_hide: true
---

# Nexpose XML 2.0 (Rapid7) Parser Documentation

## Overview

The Nexpose XML 2.0 (Rapid7) parser for DefectDojo supports importing vulnerability scan results from Rapid7's Nexpose vulnerability scanner. This parser processes XML reports containing detailed information about vulnerabilities detected across hosts and services in your environment.

## Supported File Types

The Nexpose parser accepts XML 2.0 file format. To generate this file:

1. In the Nexpose console, go to the Reports section
2. Create a new report or edit an existing one
3. Select "XML Export" as the report format
4. Ensure you select "XML 2.0" as the version
5. Run the report and download the XML file

## XML Format

### Total Fields in Nexpose XML

- Total data fields in Nexpose XML: 25 primary elements with nested structures
- Total data fields parsed into DefectDojo finding: 18 key fields mapped
- Total data fields NOT parsed: 7 (including metadata fields not relevant to findings)

### Field Mapping Details

| Data Field # | Nexpose Data Field | DefectDojo Finding Field | Parser Line # | Notes |
|--------------|------------|---------------|---------------|-------|
| 1 | vulnerability.title | title | 323 | Direct mapping to finding title |
| 2 | vulnerability.description | description | 324-325 | Converted from HTML to text |
| 3 | vulnerability.severity | severity | 316-320 | Converted from numeric (0-10) to text severity |
| 4 | test.status | active | 321 | Only vulnerable statuses are processed |
| 5 | vulnerability.cvssVector | impact | 329 | The CVSS vector string is mapped to impact |
| 6 | vulnerability.solution | mitigation | 326-328 | HTML converted to text if present |
| 7 | test.pluginOutput | description | 334-339 | Test output appended to description |
| 8 | vulnerability.references | references | 354-370 | Special formatting applied to different reference types |
| 9 | vulnerability.references.CVE | unsaved_vulnerability_ids | 371-372 | CVE references are added to vulnerability IDs list |
| 10 | vulnerability.tags | unsaved_tags | 347 | Tags are collected and mapped to unsaved_tags |
| 11 | node.address | endpoint.host | 295 | Used to create endpoint objects |
| 12 | node.names.name | endpoint.host | 295 | Hostnames are collected as alternatives to IP addresses |
| 13 | service.name | endpoint.protocol | 302-307 | Used if service name matches a known protocol |
| 14 | service.port | endpoint.port | 297 | Added to endpoint if present |
| 15 | service.protocol | endpoint.protocol | 302-307 | Used as fallback protocol if service name doesn't match |
| 16 | test.vulnerable-since | date | 341-345 | Used for finding date if USE_FIRST_SEEN is enabled |
| 17 | node.hostnames | endpoint.host | 272-274 | Hostnames associated with the node are added to a set |
| 18 | test.pci-compliance-status | Not directly mapped | 293 | Used in filtering but not mapped to a field |

### Special Processing Notes

#### Status Conversion
- The parser only processes findings with test status of "vulnerable-exploited", "vulnerable-version", or "vulnerable-potential" (line 293-294)
- All valid findings are set to active=True by default

#### Description Construction
- The main vulnerability description is converted from HTML to text (lines 324-325)
- Test output (if any) is appended to the description with newlines (lines 334-339)
- If multiple instances of the same vulnerability are found, their outputs are combined in the description

#### Severity Conversion
- Nexpose uses a numeric severity scale from 0-10
- The parser converts this to DefectDojo's text-based severity levels (lines 316-320):
  - 9-10: Critical
  - 7-8: High
  - 4-6: Medium
  - 1-3: Low
  - 0: Info

#### Deduplication
- Findings are deduplicated based on severity + vulnerability name (line 313)
- If a duplicate is found, the plugin output is appended to the description (lines 335-339)

#### Title Format
- Uses the direct title from the vulnerability definition (line 323)

#### Mitigation Construction
- Converts HTML mitigation text to plain text if present (lines 326-328)

#### References Handling
- Special formatting is applied to different reference types (lines 354-370)
- References are formatted as markdown links to the appropriate external sites for different reference sources
- Special cases for BID, CA, CERT-VN, CVE, DEBIAN, XF, and URL references
- If a CVE reference is found, it's also added to unsaved_vulnerability_ids (lines 371-372)

#### Tags Handling
- Tags from vulnerability definition are collected and added to finding.unsaved_tags (line 347)

#### Endpoint Creation
- Endpoints are created from host information (line 295)
- Port information is added if available (line 297)
- Protocol is determined from service name if possible, otherwise falls back to service protocol (lines 302-307)
- Special handling for DNS services to record TCP/UDP protocol info (lines 301-307)

#### CVSS Processing
- CVSS vector strings are mapped directly to the impact field (line 329)

#### Common Settings for All Findings
- All findings are set to dynamic_finding=True (line 344)
- All findings are set to false_p=False and duplicate=False (lines 342-343)

### Sample Scan Data
Sample Nexpose XML 2.0 (Rapid7) scans can be found in the [unit test example scans folder](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/nexpose).

### Link To Tool
- [Rapid7 Nexpose](https://www.rapid7.com/products/nexpose/)
- [Nexpose Documentation](https://docs.rapid7.com/nexpose/)
