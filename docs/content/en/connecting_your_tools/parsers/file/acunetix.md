---
title: "Acunetix Scan"
toc_hide: true
---

# Acunetix Scan Parser Documentation

## Overview

The Acunetix Scan parser for DefectDojo supports importing vulnerability scan results from Acunetix web application security scanner. This parser processes both XML reports from Acunetix and JSON reports from Acunetix 360, providing comprehensive vulnerability data including detailed descriptions, remediation guidance, and HTTP request/response evidence.

## Supported File Types

The Acunetix parser accepts two file formats:

### JSON Format (Acunetix 360)
1. In the Acunetix 360 console, navigate to the scan results
2. Select the completed scan you want to export
3. Click "Export" and choose "JSON" as the format
4. Download the JSON file

### XML Format (Acunetix)
1. In the Acunetix console, go to the Reports section
2. Select the scan you want to export
3. Choose "Export" and select "XML" as the report format
4. Download the XML file

## JSON Format (Acunetix 360)

### Total Fields in JSON

- Total data fields in Acunetix 360 JSON output: 41 primary fields per vulnerability
- Total data fields parsed into DefectDojo finding: 11 key fields mapped
- Total data fields NOT parsed: 30

### JSON Format Field Mapping Details

| Data Field # | Acunetix 360 Data Field | DefectDojo Finding Field | Parser Line # | Notes |
|--------------|-------------------------|--------------------------|---------------|-------|
| 1 | Generated | date | 71 | Scan date parsed from top-level field, used as fallback if FirstSeenDate not present |
| 2 | Target.Duration | Not Parsed | N/A | Scan duration not captured |
| 3 | Target.Initiated | Not Parsed | N/A | Scan initiation time not captured |
| 4 | Target.ScanId | Not Parsed | N/A | Scan identifier not captured |
| 5 | Target.Url | Not Parsed | N/A | Target URL not captured at finding level |
| 6 | Certainty | Not Parsed | N/A | Confidence level not mapped |
| 7 | Classification.Capec | Not Parsed | N/A | CAPEC identifier not captured |
| 8 | Classification.Cvss | cvssv3 | 137-142 | CVSS vector extracted and cleaned from Classification.Cvss.Vector |
| 9 | Classification.Cvss31 | cvssv3 | 137-142 | CVSS 3.1 vector processed if present (same logic as Cvss) |
| 10 | Classification.Cwe | cwe | 76-81 | Extracted first CWE ID from comma-separated string, converted to integer |
| 11 | Classification.Hipaa | Not Parsed | N/A | HIPAA classification not captured |
| 12 | Classification.Iso27001 | Not Parsed | N/A | ISO 27001 classification not captured |
| 13 | Classification.Owasp | Not Parsed | N/A | OWASP classification not captured |
| 14 | Classification.OwaspProactiveControls | Not Parsed | N/A | OWASP Proactive Controls not captured |
| 15 | Classification.Pci32 | Not Parsed | N/A | PCI DSS 3.2 classification not captured |
| 16 | Classification.Wasc | Not Parsed | N/A | WASC classification not captured |
| 17 | Confirmed | Not Parsed | N/A | Confirmation status not directly mapped |
| 18 | Description | description | 74 | HTML converted to Markdown using html2text library |
| 19 | ExploitationSkills | Not Parsed | N/A | Exploitation skills assessment not captured |
| 20 | ExternalReferences | Not Parsed | N/A | External references not captured separately |
| 21 | ExtraInformation | Not Parsed | N/A | Additional information array not captured |
| 22 | FirstSeenDate | date | 159-161 | Parsed with dayfirst=True, overrides Generated date if present |
| 23 | HttpRequest.Content | unsaved_req_resp | 116-119, 155 | Stored in request field of req/resp pair |
| 24 | HttpRequest.Method | Not Parsed | N/A | HTTP method not captured separately |
| 25 | HttpRequest.Parameters | Not Parsed | N/A | Request parameters not captured |
| 26 | HttpResponse.Content | unsaved_req_resp | 120-123, 155 | Stored in response field of req/resp pair |
| 27 | HttpResponse.Duration | Not Parsed | N/A | Response duration not captured |
| 28 | HttpResponse.StatusCode | Not Parsed | N/A | HTTP status code not captured |
| 29 | Impact | impact | 125 | HTML converted to Markdown using html2text library |
| 30 | KnownVulnerabilities | Not Parsed | N/A | Known vulnerabilities array not captured |
| 31 | LastSeenDate | Not Parsed | N/A | Last seen date not captured |
| 32 | LookupId | references | 95-103 | Used to construct Acunetix360 issue detail URL, appended to references |
| 33 | Name | title | 73 | Vulnerability name mapped directly to title |
| 34 | ProofOfConcept | Not Parsed | N/A | Proof of concept not captured |
| 35 | RemedialActions | Not Parsed | N/A | Remedial actions not captured separately |
| 36 | RemedialProcedure | mitigation | 86-88 | HTML converted to Markdown using html2text library |
| 37 | RemedyReferences | references | 89-91 | HTML converted to Markdown, combined with LookupId URL |
| 38 | Severity | severity | 82-84 | Converted to title case, validated against allowed values |
| 39 | State | risk_accepted, false_p, active | 144-152 | Used to determine risk acceptance and false positive status |
| 40 | Type | Not Parsed | N/A | Vulnerability type identifier not captured |
| 41 | Url | unsaved_endpoints | 156 | Parsed into Endpoint object using Endpoint.from_uri() |

### JSON Format Special Processing Notes

#### Status Conversion
The `State` field is processed with special logic (lines 144-152):
- **"AcceptedRisk"** in State → `risk_accepted=True`, `active=False`
- **"FalsePositive"** in State → `false_p=True`, `active=False`
- State is split by comma and each value is stripped before checking
- Default state: `active=True` (line 133)

#### Severity Conversion
Severity mapping (lines 82-84):
- Valid values: "Info", "Low", "Medium", "High", "Critical"
- Invalid values are converted to "Info" as default
- Output is converted to title case using `.title()` method

#### Description Construction
Description field processing (line 74):
- HTML content from `Description` field is converted to Markdown using `html2text` library
- `html2text.HTML2Text()` instance configured with `body_width = 0` (line 72) to prevent line wrapping
- `.handle()` method processes HTML tags into Markdown format
- Preserves formatting like headers, lists, links, and code blocks

#### Title Format
Title is taken directly from the `Name` field without modification (line 73).

#### Mitigation Construction
Mitigation field processing (lines 86-88):
- Sourced from `RemedialProcedure` field
- HTML converted to Markdown using html2text
- Set to `None` if `RemedialProcedure` is null in scanner output

#### Impact Construction
Impact field processing (line 125):
- Sourced from `Impact` field
- HTML converted to Markdown using html2text
- Conditional check ensures field is not None before processing

#### References Construction
References field is built from multiple sources (lines 89-103):
- **RemedyReferences**: HTML converted to Markdown if present
- **LookupId**: Constructs URL `https://online.acunetix360.com/issues/detail/{lookupId}`
- If RemedyReferences is None, only LookupId URL is used
- If RemedyReferences exists, LookupId URL is prepended with newline separator

#### Date Processing
Date handling uses two sources (lines 71, 159-161):
- **Primary**: `FirstSeenDate` from vulnerability object (parsed with `dayfirst=True`)
- **Fallback**: `Generated` from top-level scan metadata
- Uses `dateutil.parser.parse()` for flexible date parsing
- FirstSeenDate overrides Generated date if present

#### CVSS Processing
CVSS vector extraction (lines 137-142):
- Checks for nested path: `Classification` → `Cvss` → `Vector`
- Uses `cvss_parser.parse_cvss_from_text()` to parse vector string
- Extracts first CVSS object from parsed results
- Calls `.clean_vector()` method to normalize format
- Supports both CVSS 3.0 and 3.1

#### CWE Processing
CWE extraction (lines 76-81):
- Navigates to `Classification.Cwe` field
- Splits by comma to handle multiple CWE IDs
- Takes first CWE ID using `[0]` index
- Converts to integer, wrapped in try/except to handle conversion errors
- Sets to `None` if conversion fails or field is missing

#### Request/Response Handling
HTTP request and response processing (lines 116-123, 155):
- Extracts `HttpRequest.Content` and `HttpResponse.Content`
- Validates that content exists and has length > 0
- Uses fallback messages: "Request Not Found" or "Response Not Found"
- Stored in `unsaved_req_resp` as list of dictionaries with "req" and "resp" keys
- Multiple req/resp pairs can be accumulated for duplicate findings (lines 163-165)

#### Endpoint Handling
URL processing (line 156):
- Uses `Endpoint.from_uri()` static method to parse URL
- Creates DefectDojo Endpoint object with protocol, host, port, path
- Stored in `unsaved_endpoints` list
- Multiple endpoints can be accumulated for duplicate findings (lines 163-165)

#### Deduplication
Deduplication logic (lines 157-167):
- Uses `title` and `description` as deduplication keys (lines 64-68)
- Maintains `dupes` dictionary with title as key
- For duplicate findings:
  - Extends `unsaved_req_resp` list with additional request/response pairs
  - Extends `unsaved_endpoints` list with additional URLs
- Returns deduplicated list of findings (line 168)

#### Common Settings for All Findings
All findings are set with:
- `static_finding = True` (line 133)
- `dynamic_finding = False` (line 133)

## XML Format (Acunetix)

### Total Fields in XML

- Total data fields in Acunetix XML output: 58 primary fields across multiple levels
- Total data fields parsed into DefectDojo finding: 20 key fields mapped
- Total data fields NOT parsed: 38

### XML Format Field Mapping Details

| Data Field # | Acunetix Data Field | DefectDojo Finding Field | Parser Line # | Notes |
|--------------|---------------------|--------------------------|---------------|-------|
| 1 | ScanGroup/@ExportedOn | Not Parsed | N/A | Export timestamp not used |
| 2 | Scan/Name | Not Parsed | N/A | Scan name not captured |
| 3 | Scan/ShortName | Not Parsed | N/A | Scan short name not captured |
| 4 | Scan/StartURL | unsaved_endpoints | 77-78, 163-171 | Parsed to extract host/port/protocol for endpoint creation |
| 5 | Scan/StartTime | date | 80-83 | Parsed with dateutil.parser, converted to date object |
| 6 | Scan/FinishTime | Not Parsed | N/A | Scan finish time not captured |
| 7 | Scan/ScanTime | Not Parsed | N/A | Total scan duration not captured |
| 8 | Scan/Aborted | Not Parsed | N/A | Scan abort status not captured |
| 9 | Scan/Responsive | Not Parsed | N/A | Target responsive status not captured |
| 10 | Scan/Banner | Not Parsed | N/A | Server banner not captured |
| 11 | Scan/Os | Not Parsed | N/A | Operating system not captured |
| 12 | Scan/WebServer | Not Parsed | N/A | Web server type not captured |
| 13 | Scan/Technologies | Not Parsed | N/A | Technologies detected not captured |
| 14 | Crawler/@StartUrl | Not Parsed | N/A | Crawler start URL not captured |
| 15 | Crawler/Cookies | Not Parsed | N/A | Cookies not captured |
| 16 | Crawler/SiteFiles/SiteFile/@id | Not Parsed | N/A | Site file ID not captured |
| 17 | Crawler/SiteFiles/SiteFile/Name | Not Parsed | N/A | Site file name not captured |
| 18 | Crawler/SiteFiles/SiteFile/URL | Not Parsed | N/A | Site file URL not captured |
| 19 | Crawler/SiteFiles/SiteFile/FullURL | Not Parsed | N/A | Site file full URL not captured |
| 20 | ReportItem/@id | Not Parsed | N/A | Report item ID not used for deduplication |
| 21 | ReportItem/@color | Not Parsed | N/A | Color coding not captured |
| 22 | ReportItem/Name | title | 86 | Mapped directly to finding title |
| 23 | ReportItem/ModuleName | Not Parsed | N/A | Scanner module name not captured |
| 24 | ReportItem/Details | description | 124-128 | Appended to description with "**Details:**" header if present |
| 25 | ReportItem/Affects | unsaved_endpoints | 168 | Used as endpoint path |
| 26 | ReportItem/Parameter | Not Parsed | N/A | Parameter name not captured |
| 27 | ReportItem/AOP_SourceFile | Not Parsed | N/A | Source file not captured |
| 28 | ReportItem/AOP_SourceLine | Not Parsed | N/A | Source line number not captured |
| 29 | ReportItem/AOP_Additional | Not Parsed | N/A | Additional AOP info not captured |
| 30 | ReportItem/IsFalsePositive | false_p | 91-93 | Converted to boolean via get_false_positive() function (line 220) |
| 31 | ReportItem/Severity | severity | 87 | Converted via get_severity() function (lines 203-213) |
| 32 | ReportItem/Type | Not Parsed | N/A | Vulnerability type not captured |
| 33 | ReportItem/Impact | impact | 96-97 | Mapped directly if present and not empty |
| 34 | ReportItem/Description | description | 88-90 | Converted from HTML to text using html2text, stripped |
| 35 | ReportItem/DetailedInformation | Not Parsed | N/A | Detailed information field not captured |
| 36 | ReportItem/Recommendation | mitigation | 98-101 | Mapped directly if present and not empty |
| 37 | ReportItem/TechnicalDetails | description | 130-135 | Appended to description with "**TechnicalDetails:**" header if present |
| 38 | ReportItem/TechnicalDetails/Request | unsaved_req_resp | 138-148 | Each request added to req_resp list; triggers dynamic_finding=True, static_finding=False |
| 39 | ReportItem/CWEList/CWE | cwe | 103-106 | Extracted number via get_cwe_number() function (lines 192-200) |
| 40 | ReportItem/CWEList/CWE/@id | Not Parsed | N/A | CWE ID attribute not used (text content used instead) |
| 41 | ReportItem/CVEList | Not Parsed | N/A | CVE list not captured |
| 42 | ReportItem/CVSS/Descriptor | Not Parsed | N/A | CVSS v2 descriptor not captured |
| 43 | ReportItem/CVSS/Score | Not Parsed | N/A | CVSS v2 score not captured |
| 44 | ReportItem/CVSS/AV | Not Parsed | N/A | CVSS v2 attack vector not captured |
| 45 | ReportItem/CVSS/AC | Not Parsed | N/A | CVSS v2 attack complexity not captured |
| 46 | ReportItem/CVSS/Au | Not Parsed | N/A | CVSS v2 authentication not captured |
| 47 | ReportItem/CVSS/C | Not Parsed | N/A | CVSS v2 confidentiality not captured |
| 48 | ReportItem/CVSS/I | Not Parsed | N/A | CVSS v2 integrity not captured |
| 49 | ReportItem/CVSS/A | Not Parsed | N/A | CVSS v2 availability not captured |
| 50 | ReportItem/CVSS/E | Not Parsed | N/A | CVSS v2 exploitability not captured |
| 51 | ReportItem/CVSS/RL | Not Parsed | N/A | CVSS v2 remediation level not captured |
| 52 | ReportItem/CVSS/RC | Not Parsed | N/A | CVSS v2 report confidence not captured |
| 53 | ReportItem/CVSS3/Descriptor | cvssv3 | 115-119 | Parsed using cvss_parser.parse_cvss_from_text(), cleaned vector stored |
| 54 | ReportItem/CVSS3/Score | Not Parsed | N/A | CVSS v3 score not captured (calculated by DefectDojo from vector) |
| 55 | ReportItem/CVSS3/TempScore | Not Parsed | N/A | CVSS v3 temporal score not captured |
| 56 | ReportItem/CVSS3/EnvScore | Not Parsed | N/A | CVSS v3 environmental score not captured |
| 57 | ReportItem/CVSS3/[AV/AC/PR/UI/S/C/I/A/E/RL/RC] | Not Parsed | N/A | Individual CVSS v3 metrics not captured (vector string used instead) |
| 58 | ReportItem/References/Reference/Database | references | 107-112 | Combined with URL in markdown format |
| 59 | ReportItem/References/Reference/URL | references | 107-112 | Combined with Database in markdown format: `[Database](URL)` |

### XML Format Special Processing Notes

#### Status Conversion
- Only `false_p` is set based on the `IsFalsePositive` field (lines 91-93, function at line 220)
- Default values:
  - `active`: Not explicitly set (DefectDojo default applies)
  - `verified`: Not explicitly set (DefectDojo default applies)
  - `false_p`: Set via `get_false_positive()` function converting string to boolean

#### Severity Conversion
The `get_severity()` function (lines 203-213) maps Acunetix severity values to DefectDojo format:

| Acunetix Value | DefectDojo Value |
|----------------|------------------|
| "high" | "High" |
| "medium" | "Medium" |
| "low" | "Low" |
| "informational" | "Info" |
| (any other) | "Critical" |

#### Description Construction
The description field is built from multiple sources (lines 88-135):

1. **Base Description** (lines 88-90): `ReportItem/Description` converted from HTML to text using `html2text.html2text()` and stripped
2. **Details Section** (lines 124-128): If `ReportItem/Details` exists and is not empty, appended with header `\n\n**Details:**\n{html2text conversion}`
3. **Technical Details Section** (lines 130-135): If `ReportItem/TechnicalDetails` exists and is not empty, appended with header `\n\n**TechnicalDetails:**\n\n{raw text}`

For duplicate findings (lines 188-193), additional Details are appended with separator: `\n-----\n\n**Details:**\n`

#### Title Format
Title is taken directly from `ReportItem/Name` without modification (line 86).

#### Mitigation Construction
Mitigation is taken directly from `ReportItem/Recommendation` if present and not empty (lines 98-101). No additional formatting or construction occurs.

#### Date Processing
The `StartTime` field is parsed using `dateutil.parser.parse()` with `dayfirst=True` parameter (lines 80-83), then converted to a date object. This date is applied to all findings from that scan (line 102).

Format example: "27/02/2020, 12:56:09" → date object

#### References Handling
References are constructed from `ReportItem/References/Reference` elements (lines 107-112):
- Each reference creates a markdown link: `[Database](URL)`
- If Database field is empty, URL is used as the link text
- Multiple references are joined with newlines
- Format: ` * [Database](URL)\n * [Database2](URL2)`

#### Endpoint Creation
Endpoints are created from two sources (lines 163-171):
1. **Host/Port/Protocol**: Extracted from `Scan/StartURL` using hyperlink.parse()
   - If StartURL doesn't contain ":", "//" is prepended (lines 77-78)
   - Protocol set only if scheme is not None and not empty (lines 169-170)
2. **Path**: Taken from `ReportItem/Affects` (line 168)

Each finding gets one endpoint stored in `unsaved_endpoints` list.

#### Static vs Dynamic Finding Classification
The parser determines finding type based on presence of requests (lines 138-148):
- **Default** (lines 94-95): `static_finding=True`, `dynamic_finding=False`
- **If requests present** (lines 142-145): `static_finding=False`, `dynamic_finding=True`

#### Request/Response Handling
Requests are extracted from `ReportItem/TechnicalDetails/Request` elements (lines 138-148):
- Each request is added to `unsaved_req_resp` list as a dictionary: `{"req": request.text or "", "resp": ""}`
- Response field is always empty string
- Multiple requests can exist per finding

#### CWE Extraction
The `get_cwe_number()` function (lines 192-200) extracts the numeric CWE ID:
- Input format: "CWE-200"
- Splits on "-" and takes second element
- Converts to integer
- Returns None if input is None

#### CVSS v3 Processing
CVSS v3 vector is parsed using the `cvss` library (lines 115-119):
- Uses `cvss_parser.parse_cvss_from_text()` to parse the descriptor
- Takes first object from returned list
- Calls `.clean_vector()` to get standardized format
- Only processes if at least one CVSS object is returned

#### Deduplication
Findings are deduplicated based on SHA256 hash from concatenated fields (lines 172-181):
- `finding.title`
- `str(finding.impact)`
- `str(finding.mitigation)`

When duplicates are detected (lines 182-197):
- Details are appended to description with separator `\n-----\n\n**Details:**\n`
- Endpoints are extended to the existing finding
- Request/response pairs are extended to the existing finding
- `nb_occurences` counter is incremented

#### Occurrence Tracking
Each finding starts with `nb_occurences=1` (line 95). When duplicates are found, this counter is incremented (line 196).

## Unparsed Fields

### JSON Format Unparsed Fields
- Target.Duration
- Target.Initiated
- Target.ScanId
- Target.Url
- Certainty
- Classification.Capec
- Classification.Hipaa
- Classification.Iso27001
- Classification.Owasp
- Classification.OwaspProactiveControls
- Classification.Pci32
- Classification.Wasc
- Confirmed
- ExploitationSkills
- ExternalReferences
- ExtraInformation
- HttpRequest.Method
- HttpRequest.Parameters
- HttpResponse.Duration
- HttpResponse.StatusCode
- KnownVulnerabilities
- LastSeenDate
- ProofOfConcept
- RemedialActions
- Type

### XML Format Unparsed Fields
- ScanGroup/@ExportedOn
- Scan/Name
- Scan/ShortName
- Scan/FinishTime
- Scan/ScanTime
- Scan/Aborted
- Scan/Responsive
- Scan/Banner
- Scan/Os
- Scan/WebServer
- Scan/Technologies
- Crawler/@StartUrl
- Crawler/Cookies
- Crawler/SiteFiles (all sub-fields)
- ReportItem/@id
- ReportItem/@color
- ReportItem/ModuleName
- ReportItem/Parameter
- ReportItem/AOP_SourceFile
- ReportItem/AOP_SourceLine
- ReportItem/AOP_Additional
- ReportItem/Type
- ReportItem/DetailedInformation
- ReportItem/CWEList/CWE/@id
- ReportItem/CVEList
- ReportItem/CVSS (all CVSS v2 fields)
- ReportItem/CVSS3/Score
- ReportItem/CVSS3/TempScore
- ReportItem/CVSS3/EnvScore
- ReportItem/CVSS3 individual metrics

### Sample Scan Data
Sample Acunetix scans can be found in the [unit test example scans folder](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/acunetix).

### Link To Tool
- [Acunetix](https://www.acunetix.com/)
- [Acunetix 360](https://www.acunetix.com/product/acunetix-360/)
- [Acunetix Documentation](https://www.acunetix.com/resources/)

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

**JSON Format:**
- title
- description

**XML Format:**
- title
- impact
- mitigation