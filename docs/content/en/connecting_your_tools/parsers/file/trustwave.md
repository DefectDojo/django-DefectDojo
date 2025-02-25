---
title: "Trustwave"
toc_hide: true
---

## File Types
Trustwave vulnerability scan reports can be exported/imported in CSV format.

### Total Fields in CSV: 13
Fields in order of appearance:
1. Status (Not mapped)
2. IP - Used for endpoint host if Domain is empty
3. Target Name (Not mapped)
4. Domain - Primary choice for endpoint host
5. Vulnerability Name - Maps to finding title
6. Description - Maps to finding description
7. Remediation - Maps to finding mitigation 
8. Protocol - Added to endpoint if present
9. Port - Added to endpoint port if present, converted to integer
10. Severity - Mapped through severity levels:
    - I = Info
    - L = Low
    - M = Medium
    - H = High
    - C = Critical
11. CVE - Added to vulnerability IDs list
12. Service (Not mapped)
13. Evidence - Maps to finding references

### Field Mapping Details
For each finding created, the parser:
- Creates endpoints by combining Domain/IP, Port, and Protocol fields
- Sets default nb_occurences to 1, incremented for duplicates 
- Uses SHA256 hash of severity + title + description for deduplication
- Defaults severity to Low if mapping not matched

### Sample Scan Data
Sample Trustwave scans can be found in the [unit tests folder](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/trustwave).

### Link To Tool
[Trustwave](https://www.trustwave.com/en-us/) provides vulnerability scanning services through their SecureConnect platform.
