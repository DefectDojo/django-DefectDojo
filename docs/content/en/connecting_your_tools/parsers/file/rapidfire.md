---
title: Rapidfire CSV Parser
toc_hide: true
---

# Rapidfire CSV Parser

## CSV Field Mappings

Total Fields in CSV: 17

| CSV Field | Finding Field | Parser Line # | Notes |
|-----------|---------------|---------------|-------|
| IP Address | endpoints[].host | 162-173 | Used if hostname not available |
| Hostname | endpoints[].host | 162-173 | Primary choice for endpoint host |
| MAC Address | description | 134-136 | Added to description with "MAC Address:" prefix |
| Severity | severity | 149 | Capitalized and validated against SEVERITIES, defaults to Info |
| Issue | title | 107-110 | Direct mapping, stripped of whitespace |
| Ports | endpoints[].port | 165-166 | Extracted number before "/" using regex |
| OID | vuln_id_from_tool | 152 | Direct mapping |
| CVE | unsaved_vulnerability_ids | 176-177 | Split on comma, filtered to valid CVE IDs |
| Last Detected | date | 151 | Parsed to datetime using dateutil.parser |
| Known Exploited Vulnerability | description | 131-132 | Added to description with prefix |
| Summary | description | 117-118 | Added to description with "Summary:" prefix |
| Vulnerability Detection Result | description | 119-120 | Added to description with prefix |
| Solution | mitigation | 150 | Direct mapping |
| Vulnerability Insight | impact | 82-103 | Formatted with CVEs into impact field |
| Vulnerability Detection Method | description | 121-122 | Added to description with prefix |
| References | references | 70-124 | Formatted into markdown list of links |
| Known To Be Used In Ransomware Campaigns | description, tags | 137-138, 179-180 | Adds warning to description and "ransomware" tag |

## Summary

* Total CSV Fields: 17
* Mapped Fields: 17
* Unmapped Fields: 0

## Additional Finding Field Settings

| Finding Field | Value | Parser Line # | Notes |
|---------------|-------|---------------|-------|
| test | test parameter | 153 | Set from test parameter passed to get_findings |
| dynamic_finding | True | 153 | Hardcoded to True for all findings |
| static_finding | False | 154 | Hardcoded to False for all findings |

## Processing Notes

* Deduplication is performed using combination of title, IP address, hostname and port
* For duplicate findings, the existing finding is updated rather than creating a new one
* The parser uses csv.DictReader with comma delimiter and quote character
* Empty rows are skipped
* References are formatted into a readable markdown list with descriptive link text
* Impact field is specially formatted to combine vulnerability insight and CVE details
* Date parsing handles various formats and falls back to current time
* Port extraction handles various formats like "8080/tcp" or "443/tcp (https)"

### File Types
The Rapidfire parser accepts CSV files exported from Rapidfire vulnerability scanner. The CSV should contain vulnerability findings with fields including IP address, hostname, severity, issue details, CVEs, and other metadata.

### Sample Scan Data
Sample scan data for the Rapidfire CSV parser can be found in the [unittests/scans/rapidfire](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/rapidfire) directory. 
There are samples for:
* `one_vuln.csv` - A file containing a single vulnerability finding
* `many_vulns.csv` - A file containing multiple vulnerability findings
* `no_vuln.csv` - An empty scan with no vulnerabilities

### Link To Tool
Rapidfire is a commercial vulnerability scanning tool used for network and application security assessments. For more information, visit the vendor's website [www.rapidfire.com](https://www.rapidfire.com/).
