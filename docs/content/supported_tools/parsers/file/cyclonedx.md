---
title: "CycloneDX"
toc_hide: true
---

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

## Link To Tool

- [CycloneDX Official Website](https://www.cyclonedx.org/)
- [CycloneDX Specification](https://cyclonedx.org/specification/overview/)

### Sample Scan Data

Sample CycloneDX scans can be found in the [sample scan data folder](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/cyclonedx).

## JSON Format Field Mapping Details

<details>
<summary>Click to expand Field Mapping Table</summary>

| Source Field | DefectDojo Field | Notes |
| ------------ | ---------------- | ----- |
| bomFormat | - | CycloneDX format identifier, not used in findings |
| specVersion | - | Specification version, not used in findings |
| serialNumber | - | BOM serial number, not used in findings |
| version | - | BOM version number not used in findings |
| metadata.timestamp | date | Parsed and set as finding date if present |
| components | - | Flattened into dictionary for lookup by bom-ref |
| components[].bom-ref | - | Used as key for component lookup dictionary |
| components[].type | - | Component type (library, application, etc.) not parsed |
| components[].group | component_name | Combined with name to form component_name |
| components[].name | component_name | Primary component name identifier |
| components[].version | component_version | Component version identifier |
| components[].purl | - | Package URL not directly mapped |
| vulnerabilities[].bom-ref | - | Vulnerability BOM reference not used |
| vulnerabilities[].id | title, vuln_id_from_tool, unsaved_vulnerability_ids | Used in title construction, as vuln_id_from_tool, and first vulnerability ID |
| vulnerabilities[].source.name | - | Vulnerability source name not mapped |
| vulnerabilities[].source.url | - | Vulnerability source URL not mapped |
| vulnerabilities[].references[].id | unsaved_vulnerability_ids | Additional vulnerability IDs from references |
| vulnerabilities[].references[].source.name | - | Reference source name not mapped |
| vulnerabilities[].references[].source.url | - | Reference source URL not mapped |
| vulnerabilities[].ratings[].source.name | - | Rating source name not mapped |
| vulnerabilities[].ratings[].source.url | - | Rating source URL not mapped |
| vulnerabilities[].ratings[].score | cvssv3_score | Extracted from CVSSv3 vector calculation |
| vulnerabilities[].ratings[].severity | severity | Fixed via fix_severity helper, overridden by CVSS calculation if available |
| vulnerabilities[].ratings[].method | - | Used to identify CVSSv3/CVSSv31 ratings |
| vulnerabilities[].ratings[].vector | cvssv3 | Cleaned and stored as CVSSv3 vector |
| vulnerabilities[].ratings[].justification | - | Rating justification not mapped |
| vulnerabilities[].cwes | cwe | Only first CWE mapped (limitation noted in code) |
| vulnerabilities[].description | description | Primary description field |
| vulnerabilities[].detail | description | Appended to description if present |
| vulnerabilities[].recommendation | mitigation | Mapped to mitigation field |
| vulnerabilities[].advisories[].title | references | Formatted into references string |
| vulnerabilities[].advisories[].url | references | Formatted into references string |
| vulnerabilities[].created | - | Vulnerability creation date not mapped |
| vulnerabilities[].published | - | Vulnerability publication date not mapped |
| vulnerabilities[].updated | - | Vulnerability update date not mapped |
| vulnerabilities[].credits.organizations | - | Credit organizations not mapped |
| vulnerabilities[].credits.individuals | - | Credit individuals not mapped |
| vulnerabilities[].tools | - | Tool information not mapped |
| vulnerabilities[].analysis.state | is_mitigated, active, false_p | Maps to mitigation/false positive status |
| vulnerabilities[].analysis.justification | - | Analysis justification not mapped |
| vulnerabilities[].analysis.response | - | Analysis response not mapped |
| vulnerabilities[].analysis.detail | mitigation | Appended to mitigation if vulnerability is mitigated/suppressed |
| vulnerabilities[].affects[].ref | component_name, component_version | Used to lookup component details from components dictionary |
| vulnerabilities[].affects[].versions[].range | - | Version range information not mapped |
| vulnerabilities[].affects[].versions[].status | - | Version status not mapped |

</details>

### Additional Finding Field Settings (JSON Format)

| Finding Field | Default Value |
|---------------|---------------|
| static_finding | True |
| dynamic_finding | False |
| vuln_id_from_tool | vulnerabilities[].id |

## XML Format Field Mapping Details

<details>
<summary>Click to expand Field Mapping Table</summary>

| Source Field | DefectDojo Field | Notes |
| ------------ | ---------------- | ----- |
| bom/@serialNumber | - | BOM serial number not extracted |
| bom/@version | - | BOM version not extracted |
| bom/@xmlns | - | Used for namespace validation only |
| metadata/timestamp | date | Parsed as report_date and assigned to finding.date |
| components/component/@type | - | Component type not extracted |
| components/component/@bom-ref | - | Used for internal reference mapping to link vulnerabilities to components |
| components/component/group | - | Component group not extracted |
| components/component/name | component_name | Component name stored in bom_refs and used in finding |
| components/component/version | component_version | Component version stored in bom_refs and used in finding |
| components/component/purl | - | Package URL not extracted |
| vulnerability/@bom-ref | - | Used as reference identifier for legacy format |
| vulnerability/id | vuln_id_from_tool, title, unsaved_vulnerability_ids | Primary vulnerability identifier, used in title and vulnerability IDs list |
| vulnerability/source/name | - | Vulnerability source name not extracted |
| vulnerability/source/url | - | Vulnerability source URL not extracted |
| vulnerability/references/reference/id | unsaved_vulnerability_ids | Additional vulnerability IDs (e.g., CVE) added to vulnerability IDs list |
| vulnerability/references/reference/source/name | - | Reference source name not extracted |
| vulnerability/references/reference/source/url | - | Reference source URL not extracted |
| vulnerability/ratings/rating/source/name | - | Rating source name not extracted |
| vulnerability/ratings/rating/source/url | - | Rating source URL not extracted |
| vulnerability/ratings/rating/score | cvssv3_score | Calculated from CVSS vector via cvssv3.severities() |
| vulnerability/ratings/rating/severity | severity | Converted via Cyclonedxhelper().fix_severity() |
| vulnerability/ratings/rating/method | - | Used to identify CVSSv3/CVSSv31 ratings |
| vulnerability/ratings/rating/vector | cvssv3 | Cleaned via cvssv3.clean_vector() |
| vulnerability/ratings/rating/justification | - | Rating justification not extracted |
| vulnerability/cwes/cwe | cwe | First CWE only (multiple CWEs not supported), converted to integer |
| vulnerability/description | description | Main vulnerability description |
| vulnerability/detail | description | Appended to description with newline separator |
| vulnerability/recommendation | mitigation | Recommendation text mapped to mitigation field |
| vulnerability/advisories/advisory/title | references | Formatted as "**Title:** {title}\n" and added to references |
| vulnerability/advisories/advisory/url | references | Formatted as "**URL:** {url}\n" and added to references |
| vulnerability/created | - | Vulnerability creation date not extracted |
| vulnerability/published | - | Vulnerability publication date not extracted |
| vulnerability/updated | - | Vulnerability update date not extracted |
| vulnerability/credits/* | - | Credits (organizations/individuals) not extracted |
| vulnerability/tools/tool/* | - | Tool information (vendor/name/version/hashes) not extracted |
| vulnerability/analysis/state | is_mitigated, active, false_p | Maps states to finding status flags |
| vulnerability/analysis/justification | - | Analysis justification not extracted |
| vulnerability/analysis/responses | - | Analysis responses not extracted |
| vulnerability/analysis/detail | mitigation | Appended to mitigation with explanatory text when vulnerability is inactive |
| vulnerability/affects/target/ref | component_name, component_version | Resolved via bom_refs lookup to get component details |
| vulnerability/affects/target/versions | - | Version ranges not extracted |

</details>

### Additional Finding Field Settings (XML Format)

| Finding Field | Default Value |
|---------------|---------------|
| static_finding | True |
| dynamic_finding | False |
| vuln_id_from_tool | vulnerability/id |

## Special Processing Notes

### Date Processing

**JSON Format:** The parser extracts the report date from `metadata.timestamp` and assigns it to all Findings.
**XML Format:** The parser extracts the report date from `metadata/timestamp` and assigns it to all Findings.

### Status Conversion

Both formats map the `analysis.state` field to DefectDojo status flags:

**JSON Format:**
- **"resolved", "resolved_with_pedigree", "not_affected"** → `is_mitigated=True`, `active=False`
- **"false_positive"** → `false_p=True`, `active=False`
- **Other states or missing** → Default values (`active=True`, `is_mitigated=False`, `false_p=False`)

**XML Format:**
- **"resolved", "resolved_with_pedigree", "not_affected"** → `is_mitigated=True`, `active=False`
- **"false_positive"** → `false_p=True`, `active=False`
- **All other states** → Default values (`active=True`, `is_mitigated=False`, `false_p=False`)

### Severity Conversion

**JSON Format:** Severity processing occurs in two stages:
1. **Initial Severity**: Extracted from first rating's `severity` field, processed through `Cyclonedxhelper().fix_severity()` to normalize values, defaults to "Medium" if no ratings present
2. **CVSS-based Override**: If rating method is "CVSSv3" or "CVSSv31", extracts vector and calculates severity from CVSS vector using `cvssv3.severities()[0]`

**XML Format:** Severity values are processed through `Cyclonedxhelper().fix_severity()` which normalizes severity strings to DefectDojo's expected format (e.g., "critical" → "Critical"). When CVSS vector is present:
- If severity is provided in rating, it's used after normalization
- If severity is not provided, it's calculated from CVSS vector via `cvssv3.severities()[0]`

### Description Construction

**JSON Format (lines 28-33):**
1. Primary content from `vulnerabilities[].description`
2. If `vulnerabilities[].detail` exists, appended with newline separator
3. If both are missing, defaults to "Description was not provided."

**XML Format:** Description is built from multiple fields:
1. **Primary description** from `vulnerability/description`
2. **Detail appended** from `vulnerability/detail` if present: `description += f"\n{detail}"`
3. **Fallback description** (lines 97-104) when description is missing, constructed from:
   - `**Ref:** {ref}`
   - `**Id:** {vuln_id}`
   - `**Severity:** {severity}`

### Title Format

Both formats consistently format titles as:
```
{component_name}:{component_version} | {vulnerability_id}
```

**JSON Format:**
```python
title = f"{component_name}:{component_version} | {vuln_id}"
```

**XML Format:**
```python
title = f"{component_name}:{component_version} | {vuln_id}"
```

Example: `jackson-databind:2.9.4 | SNYK-JAVA-COMFASTERXMLJACKSONCORE-32111`

### Mitigation Construction

**JSON Format:**
1. Primary content from `vulnerabilities[].recommendation`
2. If vulnerability is mitigated/suppressed (analysis.state), appends:
   ```
   **This vulnerability is mitigated and/or suppressed:** {analysis.detail}
   ```

**XML Format:** Mitigation field is built from:
1. **Primary source**: `vulnerability/recommendation`
2. **Legacy format**: Concatenated recommendations from `v:recommendations/v:recommendation`
3. **Analysis detail**: When vulnerability is inactive (mitigated/false positive), analysis detail is appended:
   ```
   \n**This vulnerability is mitigated and/or suppressed:** {detail}\n
   ```

### References Construction

**JSON Format:**
```
**Title:** {advisory.title}
**URL:** {advisory.url}

```
Each advisory is separated by double newlines.

**XML Format:**
```
**Title:** {advisory/title}
**URL:** {advisory/url}

```
Each advisory is separated by double newlines.

### Component Lookup

**JSON Format:** Components are flattened into a dictionary using `bom-ref` as the key. The `_get_component()` helper method retrieves component name and version from this dictionary using the `affects[].ref` value.

**XML Format:** For vulnerabilities in the `affects` section, components are resolved via `bom_refs` lookup:
1. Extract `ref` from `affects/target/ref`
2. Look up component details from `bom_refs` dictionary populated during component parsing
3. Extract `component_name` and `component_version` from the reference

### Vulnerability IDs Collection

**JSON Format:**
1. Primary ID from `vulnerabilities[].id` (if present)
2. Additional IDs from `vulnerabilities[].references[].id` (if present)
3. Stored in `unsaved_vulnerability_ids` list

**XML Format:** Multiple vulnerability identifiers are collected into `unsaved_vulnerability_ids` list:
1. **Primary ID** from `vulnerability/id`
2. **Reference IDs** from `vulnerability/references/reference/id`

This allows linking CVE IDs and other identifiers to the same finding.

### CWE Handling

**JSON Format:** Only the first CWE is mapped. The parser logs a debug message if multiple CWEs are present, noting this is not supported by the parser API.

**XML Format:** CWE extraction:
- Supports both legacy namespace (`v:cwes/v:cwe`) and 1.4 spec namespace (`b:cwes/b:cwe`)
- Filters to numeric CWE values only via `cwe.text.isdigit()`
- Converts to integer
- **Limitation**: Only first CWE is used; multiple CWEs logged but not supported

### CVSS Processing

**JSON Format:** CVSS vectors are processed to extract both the vector string and calculated score.

**XML Format:** CVSS vectors are processed through `Cyclonedxhelper()._get_cvssv3()` which:
1. Parses the raw CVSS vector string
2. Returns a cvssv3 object that provides:
   - `clean_vector()` - Normalized CVSS vector string
   - `severities()[0]` - Calculated severity from vector

### Multiple Findings per Vulnerability

**JSON Format:** The parser creates **one finding per affected component**. A single vulnerability with multiple entries in the `affects` array will generate multiple DefectDojo findings, one for each affected component reference.

**XML Format:** The parser creates one finding per affected component, supporting both legacy and 1.4 specification formats.

### Namespace Handling (XML Only)

The XML parser supports multiple CycloneDX BOM versions by:
1. Extracting namespace dynamically from root element
2. Validating it starts with `http://cyclonedx.org/schema/bom/`
3. Using namespace prefixes in XPath queries throughout parsing

### Legacy Format Support (XML Only)

The XML parser supports two vulnerability formats:
1. **Legacy format**: Vulnerabilities nested under components with `v:` namespace
2. **1.4 spec format**: Vulnerabilities at root level with `b:` namespace and `affects` section
