---
title: "CycloneDX"
toc_hide: true
---

# CycloneDX Parser Documentation

The [CycloneDX](https://www.cyclonedx.org/) parser for DefectDojo supports imports from both JSON and XML formats. CycloneDX is a lightweight software bill of materials (SBOM) standard designed for use in application security contexts and supply chain component analysis.

## Supported File Types

The CycloneDX parser accepts both JSON and XML file formats. To generate these files:

### Using Anchore Grype

```bash
./grype defectdojo/defectdojo-django:1.13.1 -o cyclonedx > report.xml
```

### Using cyclonedx-bom Tool

```bash
pip install cyclonedx-bom
cyclonedx-py
```

```bash
Usage:  cyclonedx-py [OPTIONS]
Options:
  -i <path> - the alternate filename to a frozen requirements.txt
  -o <path> - the bom file to create
  -j        - generate JSON instead of XML
```

## Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln id from tool
- component name
- component version

## Sample Scan Data

Sample CycloneDX scans can be found in the [sample scan data folder](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/cyclonedx).

## Link To Tool

- [CycloneDX Official Website](https://www.cyclonedx.org/)
- [CycloneDX Specification](https://cyclonedx.org/specification/overview/)

## JSON Format

### Total Fields in JSON

- Total data fields: 45
- Total data fields parsed: 20
- Total data fields NOT parsed: 25

### JSON Format Field Mapping Details

<details>
<summary>Click to expand Field Mapping Table</summary>

| Source Field | DefectDojo Field | Parser Line # | Notes |
| ------------ | ---------------- | ------------- | ----- |
| bomFormat | - | N/A | CycloneDX format identifier, not used in findings |
| specVersion | - | N/A | Specification version, not used in findings |
| serialNumber | - | N/A | BOM serial number, not used in findings |
| version | - | N/A | BOM version number, not used in findings |
| metadata.timestamp | date | 17-20 | Parsed and set as finding date if present |
| components | - | 21, 148-156 | Flattened into dictionary for lookup by bom-ref |
| components[].bom-ref | - | 155-156 | Used as key for component lookup dictionary |
| components[].type | - | N/A | Component type (library, application, etc.) not parsed |
| components[].group | component_name | 60-61 | Combined with name to form component_name |
| components[].name | component_name | 60-61 | Primary component name identifier |
| components[].version | component_version | 60-61 | Component version identifier |
| components[].purl | - | N/A | Package URL not directly mapped |
| vulnerabilities[].bom-ref | - | N/A | Vulnerability BOM reference not used |
| vulnerabilities[].id | title, vuln_id_from_tool, unsaved_vulnerability_ids | 67, 78, 103-105 | Used in title construction, as vuln_id_from_tool, and first vulnerability ID |
| vulnerabilities[].source.name | - | N/A | Vulnerability source name not mapped |
| vulnerabilities[].source.url | - | N/A | Vulnerability source URL not mapped |
| vulnerabilities[].references[].id | unsaved_vulnerability_ids | 107-110 | Additional vulnerability IDs from references |
| vulnerabilities[].references[].source.name | - | N/A | Reference source name not mapped |
| vulnerabilities[].references[].source.url | - | N/A | Reference source URL not mapped |
| vulnerabilities[].ratings[].source.name | - | N/A | Rating source name not mapped |
| vulnerabilities[].ratings[].source.url | - | N/A | Rating source URL not mapped |
| vulnerabilities[].ratings[].score | cvssv3_score | 91-99 | Extracted from CVSSv3 vector calculation |
| vulnerabilities[].ratings[].severity | severity | 36-38, 95-97 | Fixed via fix_severity helper, overridden by CVSS calculation if available |
| vulnerabilities[].ratings[].method | - | 88-90 | Used to identify CVSSv3/CVSSv31 ratings |
| vulnerabilities[].ratings[].vector | cvssv3 | 91-99 | Cleaned and stored as CVSSv3 vector |
| vulnerabilities[].ratings[].justification | - | N/A | Rating justification not mapped |
| vulnerabilities[].cwes | cwe | 115-121 | Only first CWE mapped (limitation noted in code) |
| vulnerabilities[].description | description | 28-33, 65-66 | Primary description field |
| vulnerabilities[].detail | description | 29-33 | Appended to description if present |
| vulnerabilities[].recommendation | mitigation | 73 | Mapped to mitigation field |
| vulnerabilities[].advisories[].title | references | 43-45 | Formatted into references string |
| vulnerabilities[].advisories[].url | references | 46-48 | Formatted into references string |
| vulnerabilities[].created | - | N/A | Vulnerability creation date not mapped |
| vulnerabilities[].published | - | N/A | Vulnerability publication date not mapped |
| vulnerabilities[].updated | - | N/A | Vulnerability update date not mapped |
| vulnerabilities[].credits.organizations | - | N/A | Credit organizations not mapped |
| vulnerabilities[].credits.individuals | - | N/A | Credit individuals not mapped |
| vulnerabilities[].tools | - | N/A | Tool information not mapped |
| vulnerabilities[].analysis.state | is_mitigated, active, false_p | 123-135 | Maps to mitigation/false positive status |
| vulnerabilities[].analysis.justification | - | N/A | Analysis justification not mapped |
| vulnerabilities[].analysis.response | - | N/A | Analysis response not mapped |
| vulnerabilities[].analysis.detail | mitigation | 132-134 | Appended to mitigation if vulnerability is mitigated/suppressed |
| vulnerabilities[].affects[].ref | component_name, component_version | 53-61 | Used to lookup component details from components dictionary |
| vulnerabilities[].affects[].versions[].range | - | N/A | Version range information not mapped |
| vulnerabilities[].affects[].versions[].status | - | N/A | Version status not mapped |

</details>

### Additional Finding Field Settings (JSON Format)

| Finding Field | Default Value | Parser Line # | Notes |
|---------------|---------------|---------------|-------|
| static_finding | True | 75 | All findings marked as static |
| dynamic_finding | False | 76 | All findings marked as non-dynamic |
| vuln_id_from_tool | vulnerabilities[].id | 78 | Primary vulnerability identifier |

## XML Format

### Total Fields in XML

- Total data fields: 41
- Total data fields parsed: 21
- Total data fields NOT parsed: 20

### XML Format Field Mapping Details

<details>
<summary>Click to expand Field Mapping Table</summary>

| Source Field | DefectDojo Field | Parser Line # | Notes |
| ------------ | ---------------- | ------------- | ----- |
| bom/@serialNumber | - | N/A | BOM serial number not extracted |
| bom/@version | - | N/A | BOM version not extracted |
| bom/@xmlns | - | 16-19 | Used for namespace validation only |
| metadata/timestamp | date | 31-34, 246 | Parsed as report_date and assigned to finding.date |
| components/component/@type | - | N/A | Component type not extracted |
| components/component/@bom-ref | - | 40-44 | Used for internal reference mapping to link vulnerabilities to components |
| components/component/group | - | N/A | Component group not extracted |
| components/component/name | component_name | 38, 43, 216 | Component name stored in bom_refs and used in finding |
| components/component/version | component_version | 39, 44, 217 | Component version stored in bom_refs and used in finding |
| components/component/purl | - | N/A | Package URL not extracted |
| vulnerability/@bom-ref | - | 91 | Used as reference identifier for legacy format |
| vulnerability/id | vuln_id_from_tool, title, unsaved_vulnerability_ids | 92, 137, 147, 149, 196, 199 | Primary vulnerability identifier, used in title and vulnerability IDs list |
| vulnerability/source/name | - | N/A | Vulnerability source name not extracted |
| vulnerability/source/url | - | N/A | Vulnerability source URL not extracted |
| vulnerability/references/reference/id | unsaved_vulnerability_ids | 199-203 | Additional vulnerability IDs (e.g., CVE) added to vulnerability IDs list |
| vulnerability/references/reference/source/name | - | N/A | Reference source name not extracted |
| vulnerability/references/reference/source/url | - | N/A | Reference source URL not extracted |
| vulnerability/ratings/rating/source/name | - | N/A | Rating source name not extracted |
| vulnerability/ratings/rating/source/url | - | N/A | Rating source URL not extracted |
| vulnerability/ratings/rating/score | cvssv3_score | Implicit | Calculated from CVSS vector via cvssv3.severities() |
| vulnerability/ratings/rating/severity | severity | 94, 109, 165, 180, 254, 259 | Converted via Cyclonedxhelper().fix_severity() |
| vulnerability/ratings/rating/method | - | 152, 249 | Used to identify CVSSv3/CVSSv31 ratings |
| vulnerability/ratings/rating/vector | cvssv3 | 153, 155, 250, 252 | Cleaned via cvssv3.clean_vector() |
| vulnerability/ratings/rating/justification | - | N/A | Rating justification not extracted |
| vulnerability/cwes/cwe | cwe | 164-171, 263-270 | First CWE only (multiple CWEs not supported), converted to integer |
| vulnerability/description | description | 96, 176-181 | Main vulnerability description |
| vulnerability/detail | description | 177-181 | Appended to description with newline separator |
| vulnerability/recommendation | mitigation | 219 | Recommendation text mapped to mitigation field |
| vulnerability/advisories/advisory/title | references | 186-188 | Formatted as "**Title:** {title}\n" and added to references |
| vulnerability/advisories/advisory/url | references | 189-191 | Formatted as "**URL:** {url}\n" and added to references |
| vulnerability/created | - | N/A | Vulnerability creation date not extracted |
| vulnerability/published | - | N/A | Vulnerability publication date not extracted |
| vulnerability/updated | - | N/A | Vulnerability update date not extracted |
| vulnerability/credits/* | - | N/A | Credits (organizations/individuals) not extracted |
| vulnerability/tools/tool/* | - | N/A | Tool information (vendor/name/version/hashes) not extracted |
| vulnerability/analysis/state | is_mitigated, active, false_p | 272-283 | Maps states to finding status flags |
| vulnerability/analysis/justification | - | N/A | Analysis justification not extracted |
| vulnerability/analysis/responses | - | N/A | Analysis responses not extracted |
| vulnerability/analysis/detail | mitigation | 284-288 | Appended to mitigation with explanatory text when vulnerability is inactive |
| vulnerability/affects/target/ref | component_name, component_version | 207-210 | Resolved via bom_refs lookup to get component details |
| vulnerability/affects/target/versions | - | N/A | Version ranges not extracted |

</details>

### Additional Finding Field Settings (XML Format)

| Finding Field | Default Value | Parser Line # | Notes |
|---------------|---------------|---------------|-------|
| static_finding | True | 221 | All findings marked as static |
| dynamic_finding | False | 222 | All findings marked as non-dynamic |
| vuln_id_from_tool | vulnerability/id | 137, 224 | Primary vulnerability identifier |

## Special Processing Notes

### Date Processing

**JSON Format:** The parser extracts the report date from `metadata.timestamp` (lines 17-20) using `dateutil.parser.parse()` and assigns it to all findings.

**XML Format:** The parser extracts the report date from `metadata/timestamp` (lines 31-34) using `dateutil.parser.parse()` and assigns it to `finding.date` (lines 140, 246).

**Implementation:**
```python
# JSON: json_parser.py lines 17-20
report_date = None
if "metadata" in data and "timestamp" in data["metadata"]:
    report_date = dateutil.parser.parse(data["metadata"]["timestamp"])

# XML: xml_parser.py lines 31-34
report_date = tree.find("b:metadata/b:timestamp", ns)
if report_date is not None:
    report_date = dateutil.parser.parse(report_date.text)
```

### Status Conversion

Both formats map the `analysis.state` field to DefectDojo status flags:

**JSON Format (lines 123-135):**
- **"resolved", "resolved_with_pedigree", "not_affected"** → `is_mitigated=True`, `active=False`
- **"false_positive"** → `false_p=True`, `active=False`
- **Other states or missing** → Default values (`active=True`, `is_mitigated=False`, `false_p=False`)

**XML Format (lines 272-283):**
- **"resolved", "resolved_with_pedigree", "not_affected"** → `is_mitigated=True`, `active=False` (lines 276-277)
- **"false_positive"** → `false_p=True`, `active=False` (lines 278-279)
- **All other states** → Default values (`active=True`, `is_mitigated=False`, `false_p=False`)

### Severity Conversion

**JSON Format:** Severity processing occurs in two stages:
1. **Initial Severity** (lines 36-40): Extracted from first rating's `severity` field, processed through `Cyclonedxhelper().fix_severity()` to normalize values, defaults to "Medium" if no ratings present
2. **CVSS-based Override** (lines 88-99): If rating method is "CVSSv3" or "CVSSv31", extracts vector and calculates severity from CVSS vector using `cvssv3.severities()[0]`

**XML Format:** Severity values are processed through `Cyclonedxhelper().fix_severity()` (lines 109, 165, 180, 254, 259) which normalizes severity strings to DefectDojo's expected format (e.g., "critical" → "Critical"). When CVSS vector is present:
- If severity is provided in rating, it's used after normalization (lines 254, 259)
- If severity is not provided, it's calculated from CVSS vector via `cvssv3.severities()[0]` (lines 157, 260)

### Description Construction

**JSON Format (lines 28-33):**
1. Primary content from `vulnerabilities[].description`
2. If `vulnerabilities[].detail` exists, appended with newline separator
3. If both are missing, defaults to "Description was not provided." (line 65-66)

**XML Format:** Description is built from multiple fields:
1. **Primary description** from `vulnerability/description` (lines 96, 176)
2. **Detail appended** from `vulnerability/detail` if present (lines 177-181): `description += f"\n{detail}"`
3. **Fallback description** (lines 97-104) when description is missing, constructed from:
   - `**Ref:** {ref}`
   - `**Id:** {vuln_id}`
   - `**Severity:** {severity}`

### Title Format

Both formats consistently format titles as:
```
{component_name}:{component_version} | {vulnerability_id}
```

**JSON Format (line 67):**
```python
title = f"{component_name}:{component_version} | {vuln_id}"
```

**XML Format (lines 137, 212):**
```python
title = f"{component_name}:{component_version} | {vuln_id}"
```

Example: `jackson-databind:2.9.4 | SNYK-JAVA-COMFASTERXMLJACKSONCORE-32111`

### Mitigation Construction

**JSON Format (lines 73, 132-134):**
1. Primary content from `vulnerabilities[].recommendation`
2. If vulnerability is mitigated/suppressed (analysis.state), appends:
   ```
   **This vulnerability is mitigated and/or suppressed:** {analysis.detail}
   ```

**XML Format:** Mitigation field is built from:
1. **Primary source**: `vulnerability/recommendation` (line 219)
2. **Legacy format**: Concatenated recommendations from `v:recommendations/v:recommendation` (lines 141-145)
3. **Analysis detail**: When vulnerability is inactive (mitigated/false positive), analysis detail is appended (lines 284-288):
   ```
   \n**This vulnerability is mitigated and/or suppressed:** {detail}\n
   ```

### Deduplication

**Method:** No explicit deduplication - The parser does not set `unique_id_from_tool` or generate hash codes. DefectDojo will use its default deduplication based on the combination of fields: vuln_id_from_tool, component_name, and component_version.

**JSON Format:** The parser sets `vuln_id_from_tool` (line 78) which is used by DefectDojo's deduplication logic.

**XML Format:** The parser sets `vuln_id_from_tool` (lines 137, 224) which may be used by DefectDojo's deduplication algorithm.

### References Construction

**JSON Format (lines 42-49):**
```
**Title:** {advisory.title}
**URL:** {advisory.url}

```
Each advisory is separated by double newlines.

**XML Format (lines 186-192):**
```
**Title:** {advisory/title}
**URL:** {advisory/url}

```
Each advisory is separated by double newlines.

### Component Lookup

**JSON Format:** Components are flattened into a dictionary (lines 148-156) using `bom-ref` as the key. The `_get_component()` helper method (line 60-61) retrieves component name and version from this dictionary using the `affects[].ref` value.

**XML Format:** For vulnerabilities in the `affects` section, components are resolved via `bom_refs` lookup (lines 207-210):
1. Extract `ref` from `affects/target/ref`
2. Look up component details from `bom_refs` dictionary populated during component parsing (lines 40-44)
3. Extract `component_name` and `component_version` from the reference

### Vulnerability IDs Collection

**JSON Format (lines 103-111):**
1. Primary ID from `vulnerabilities[].id` (if present)
2. Additional IDs from `vulnerabilities[].references[].id` (if present)
3. Stored in `unsaved_vulnerability_ids` list

**XML Format:** Multiple vulnerability identifiers are collected into `unsaved_vulnerability_ids` list:
1. **Primary ID** from `vulnerability/id` (lines 196, 199)
2. **Reference IDs** from `vulnerability/references/reference/id` (lines 199-203)

This allows linking CVE IDs and other identifiers to the same finding.

### CWE Handling

**JSON Format:** Only the first CWE is mapped (lines 115-121). The parser logs a debug message if multiple CWEs are present, noting this is not supported by the parser API.

**XML Format:** CWE extraction (lines 164-171, 263-270):
- Supports both legacy namespace (`v:cwes/v:cwe`) and 1.4 spec namespace (`b:cwes/b:cwe`)
- Filters to numeric CWE values only via `cwe.text.isdigit()`
- Converts to integer
- **Limitation**: Only first CWE is used; multiple CWEs logged but not supported (lines 166-168, 265-267)

### CVSS Processing

**JSON Format:** CVSS vectors are processed (lines 91-99) to extract both the vector string and calculated score.

**XML Format:** CVSS vectors are processed through `Cyclonedxhelper()._get_cvssv3()` (lines 154, 251) which:
1. Parses the raw CVSS vector string
2. Returns a cvssv3 object that provides:
   - `clean_vector()` - Normalized CVSS vector string (lines 155, 252)
   - `severities()[0]` - Calculated severity from vector (lines 157, 260)

### Multiple Findings per Vulnerability

**JSON Format:** The parser creates **one finding per affected component** (lines 52-136). A single vulnerability with multiple entries in the `affects` array will generate multiple DefectDojo findings, one for each affected component reference.

**XML Format:** The parser creates one finding per affected component, supporting both legacy and 1.4 specification formats.

### Namespace Handling (XML Only)

The XML parser supports multiple CycloneDX BOM versions by:
1. Extracting namespace dynamically from root element (lines 16-19)
2. Validating it starts with `http://cyclonedx.org/schema/bom/` (lines 20-21)
3. Using namespace prefixes in XPath queries throughout parsing

### Legacy Format Support (XML Only)

The XML parser supports two vulnerability formats:
1. **Legacy format** (lines 89-172): Vulnerabilities nested under components with `v:` namespace
2. **1.4 spec format** (lines 173-289): Vulnerabilities at root level with `b:` namespace and `affects` section