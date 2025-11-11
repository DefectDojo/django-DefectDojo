---
title: "DrHeader JSON Importer"
toc_hide: true
---

# DrHeader JSON Importer Parser Documentation

The [DrHeader](https://github.com/Santandersecurityresearch/DrHeader) parser for DefectDojo supports imports from JSON format exports. This document details the parsing of DrHeader security header analysis reports into DefectDojo field mappings, unmapped fields, and location of each field's parsing code for easier troubleshooting and analysis.

## Supported File Types

The DrHeader JSON Importer parser accepts JSON file format. DrHeader is a runtime HTTP header security scanner that analyzes security headers in web application responses. The parser supports two JSON structures:

1. **Structured format**: Array of objects with `url` and `report` fields
2. **Flat format**: Direct array of findings without URL grouping

To generate a DrHeader JSON report, run:
```bash
drheader scan single https://example.com --json --output report.json
```

## Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- description

The parser does not set `unique_id_from_tool`, so DefectDojo generates a hash code based on the finding's attributes for deduplication purposes.

## Sample Scan Data

Sample DrHeader scans can be found in the [sample scan data folder](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/drheader).

## Link To Tool

- [DrHeader](https://github.com/Santandersecurityresearch/DrHeader)
- [DrHeader Documentation](https://github.com/Santandersecurityresearch/DrHeader/blob/master/README.md)

## DrHeader JSON Format (DrHeaderParser)

### Total Fields in DrHeader JSON Format

- Total data fields: 7
- Total data fields parsed: 6
- Total data fields NOT parsed: 1

### DrHeader JSON Format Field Mapping Details

<details>
<summary>Click to expand Field Mapping Table</summary>

| Scanner Field Name | DefectDojo Field | Parser Line # | Notes |
| ------------------- | ------------------- | ------------------- | ------------------- |
| url | unsaved_endpoints | 48 | Converted to Endpoint object using `Endpoint.from_uri()` |
| rule | title | 23 | Prepended with "Header : " prefix |
| message | description | 24-25 | First component of description, concatenated with URL |
| severity | severity | 33 | Converted to title case using `.title()` method (e.g., "high" → "High") |
| expected | description | 27-32 | Appended to description as "Expected values: " followed by semicolon-separated list |
| value | description | 26 | Appended to description as "Observed values: " if present |

</details>

### Additional Finding Field Settings (DrHeader JSON Format)

<details>
<summary>Click to expand Additional Settings Table</summary>

| Finding Field | Default Value | Parser Line # | Notes |
|---------------|---------------|---------------|-------|
| static_finding | False | 37 | All findings explicitly marked as dynamic (runtime scanner) |
| active | True | N/A | DefectDojo Finding model default |
| verified | False | N/A | DefectDojo Finding model default |
| false_p | False | N/A | DefectDojo Finding model default |
| test | test object | 34, 47, 50 | All findings associated with the test object passed to `get_findings()` |

</details>

### Fields Not Parsed

The following fields are present in DrHeader exports but are not currently parsed:

- **delimiter**: Present in scanner export (e.g., ";" for X-XSS-Protection) but not referenced in parser code

## Special Processing Notes

<details>
<summary>Click to expand Special Processing Details</summary>

### Date Processing

No date processing is performed. DrHeader does not include timestamp information in its JSON output.

### Status Conversion

No explicit status conversion is performed. All findings are created with default DefectDojo Finding status values:
- `active=True` (default)
- `verified=False` (default)
- `false_p=False` (default)

These are set by DefectDojo's Finding model defaults, not explicitly in the parser.

### Severity Conversion

**Line 33**: Direct mapping with title case transformation:
- Scanner values: `"high"`, `"medium"`, `"low"` (lowercase strings)
- DefectDojo values: `"High"`, `"Medium"`, `"Low"` (title case)
- Transformation: `finding["severity"].title()`

No numerical severity conversion is performed - DefectDojo automatically assigns numerical severity based on the categorical value.

### Description Construction

**Lines 24-32**: The description field is built by concatenating multiple components in this order:

1. **Base message** (line 24): `finding["message"]`
2. **URL** (line 24): Appended as `"\nURL : " + url` if URL is present
3. **Observed values** (lines 25-26): If `value` field exists, appended as `"\nObserved values: " + finding["value"]`
4. **Expected values** (lines 27-32): If `expected` array exists, appended as `"\nExpected values: "` followed by semicolon-separated list of expected values

**Example construction:**
```
Header not included in response
URL : https://example.com
Expected values: DENY; SAMEORIGIN
```

The `expected` array is processed with special formatting:
- Values are joined with `"; "` separator
- Last value has no trailing separator (checked with `if expect == finding["expected"][-1]`)
- This creates a semicolon-separated list in the description

### Title Format

**Line 23**: Title is constructed by prepending "Header : " to the rule name:
- Format: `"Header : " + finding["rule"]`
- Example: `"Header : Content-Security-Policy"`

### Mitigation Construction

No mitigation field is populated by the parser. DrHeader does not provide remediation guidance in its JSON output.

### Deduplication

The parser does not set `unique_id_from_tool`. DefectDojo will generate a hash code based on the finding's attributes (title, description, severity, etc.) for deduplication purposes.

### Static vs Dynamic Finding Classification

**Line 37**: All findings are explicitly marked as dynamic:
- `static_finding=False`

This is appropriate for DrHeader, which is a runtime HTTP header security scanner that analyzes live HTTP responses.

### Endpoint Creation

**Lines 48-49**: Endpoints are created conditionally:
- If `url` field is present in the top-level object, an Endpoint is created using `Endpoint.from_uri(url)`
- The endpoint is stored in `unsaved_endpoints` array
- If no URL is present, no endpoint is attached to the finding

### Conditional Processing Logic

**Lines 43-50**: The parser handles two different JSON structures:

1. **Structured format** (lines 45-47): Array of objects with `url` and `report` fields
   - Checks if `data[0].get("url")` is not None
   - Iterates through each URL's report array
   - Passes URL to `return_finding()` for endpoint creation

2. **Flat format** (line 50): Direct array of findings without URL grouping
   - Falls back if structured format not detected
   - Processes findings without URL/endpoint information

### Error Handling

**Lines 40-42**: The parser includes basic error handling for invalid JSON:
```python
try:
    data = json.load(filename)
except ValueError:
    data = {}
```
If JSON parsing fails, an empty dictionary is returned, resulting in no findings.

</details>
