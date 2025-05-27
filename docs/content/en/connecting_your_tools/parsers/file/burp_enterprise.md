---
title: "Burp Enterprise Scan"
toc_hide: true
---

## Overview
The Burp Enterprise Scan parser processes HTML reports from Burp Enterprise Edition and imports the findings into DefectDojo. The parser extracts vulnerability details, severity ratings, descriptions, remediation steps, and other metadata from the HTML report.

## Supported File Types
The parser accepts a Standard Report as an HTML file. To parse an XML file instead, use the [Burp XML parser](https://docs.defectdojo.com/en/connecting_your_tools/parsers/file/burp/).

See the Burp documentation for information on how to export a Standard Report: [PortSwigger Enterprise Edition Downloading reports](https://portswigger.net/burp/documentation/enterprise/work-with-scan-results/generate-reports)

## Standard Format HTML (Main Format)

### Total Fields in HTML
- Total data fields in Burp Enterprise Scan HTML output: 15
- Total data fields parsed into DefectDojo finding: 13
- Total data fields NOT parsed: 2

### Standard Format Field Mapping Details

| Data Field # | Burp Enterprise Scan Data Field | DefectDojo Finding Field | Parser Line # | Notes |
|-------------|--------------------------------|--------------------------|--------------|-------|
| 1 | Title | title | 101, 165 | Extracted from issue container h2 element and table rows with "issue-type-row" class |
| 2 | Severity | severity | 101, 168 | Extracted from table rows, mapped directly (High/Medium/Low/Info) |
| 3 | Issue Detail | description | 124-135 | Extracted from matching header "issue detail" and formatted with header |
| 4 | Issue Description | description | 124-135 | Extracted from matching header "issue description" and formatted with header |
| 5 | Issue Background | impact | 136-139 | Extracted from matching header "issue background" and formatted with header |
| 6 | Issue Remediation | impact | 136-139 | Extracted from matching header "issue remediation" and formatted with header |
| 7 | Remediation Detail | mitigation | 140-143 | Extracted from matching header "remediation detail" and formatted with header |
| 8 | Remediation Background | mitigation | 140-143 | Extracted from matching header "remediation background" and formatted with header |
| 9 | References | references | 144-152 | Extracted from matching header "references" and formatted with links |
| 10 | Vulnerability Classifications | references, cwe | 144-157 | Extracts vulnerability IDs (including CWE numbers) and adds to references section |
| 11 | Request | request_response | 124-135, 190-195 | Stored as request part of request/response pair in evidence container |
| 12 | Response | request_response | 124-135, 190-195 | Stored as response part of request/response pair in evidence container |
| 13 | Endpoint URL | endpoints | 88-101 | Combined from base URL (e.g., "https://instance.example.com") and path (e.g., "/fe/m3/m-login") |
| 14 | Confidence Level | Not Parsed | - | Shown in HTML report (Certain/Firm/Tentative) but not extracted to findings |
| 15 | Issue ID/Anchor | Not Parsed | - | HTML anchor tags like "#7459896704422157312" are not extracted |

### Field Mapping Details
The parser has different handling logic for various sections of the Burp Enterprise report:

- For table content sections (using `table_contents_xpath`), the parser extracts:
  - Base endpoint from h1 elements (e.g., "https://instance.example.com")
  - Finding titles from elements with "issue-type-row" class (e.g., "Strict transport security not enforced")
  - Finding paths and severities from table rows
  - Combines base endpoint with path to construct full endpoints

- For vulnerability details sections (using `vulnerability_list_xpath`), the parser extracts:
  - Title from h2 elements
  - Various content sections based on h3 headers matching predefined categories:
    - Description headers: "issue detail", "issue description"
    - Impact headers: "issue background", "issue remediation"
    - Mitigation headers: "remediation detail", "remediation background"
    - References headers: "vulnerability classifications", "references"
    - Request/Response headers: "request", "response"

### Special Processing Notes

#### Date Processing
No special date processing is performed. The parser uses the current date for the finding.

#### Status Conversion
All findings are set with default status values:
- `false_p = False`
- `duplicate = False`
- `out_of_scope = False`
- `mitigated = None`
- `active = True`
- `verified = False`

#### Severity Conversion
Severity values are directly mapped from the Burp report without conversion.

#### Description Construction
The description field is constructed by combining content from "issue detail" and "issue description" sections. The content is formatted with headers and the original text, including proper formatting of lists, links, and other HTML elements. The description typically begins with "**Issue detail**:" or "**Issue description**:" followed by the content, with multiple sections separated by "---" markdown dividers.

#### Title Format
Finding titles are extracted directly from the h2 elements in issue containers or from table rows with the "issue-type-row" class.

#### Mitigation Construction
The mitigation field is constructed by combining content from "remediation detail" and "remediation background" sections, with proper formatting.

#### Deduplication
No explicit deduplication logic is implemented in the parser. DefectDojo's standard deduplication will apply based on the hash_code generated from the finding details.

#### Tags Handling
No specific tag handling is implemented in the parser.

#### Common settings for all findings
All findings are set with:
- `static_finding = False`
- `dynamic_finding = True`

## Unique Parser Characteristics
This parser has special handling for different section types within the HTML report:
- It handles both the main vulnerability data in "issue-container" divs and table-based data separately
- It includes processing for evidence containers with request/response pairs
- It performs formatting of HTML content including links, lists, and other elements to maintain readable descriptions
- It extracts CWE numbers and vulnerability classifications from reference sections

### Sample Scan Data
Sample Burp Enterprise Scan scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/burp_enterprise).

### Link to Tool
[Burp Enterprise Edition](https://portswigger.net/burp/enterprise)
