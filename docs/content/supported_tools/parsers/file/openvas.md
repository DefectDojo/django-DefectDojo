---
title: "OpenVAS Parser"
toc_hide: true
---
You can upload the results of an OpenVAS/Greenbone report in either .csv or .xml format.

### Sample Scan Data
Sample OpenVAS scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/openvas).

### Parser versions
The OpenVAS parser has two versions: Version 2 and the legacy version. Only version 2 should be used going forward. This documentation assumes Version 2 going forward.

Version 2 comes with a number of improvements:
- Use of a hash code algorithm for deduplication
- Increased consistency in parsing between the XML and CSV parsers.
- Combined findings where the only differences are in fields that cannot be rehashed due to inconsistent values between scans (e.g. fields containing timestamps or packet IDs). This prevents duplicates if the vulnerability is found multiple times on the same endpoint.
- Increased parser value coverage
- Heuristic for fix_available detection
- Updated mapping to DefectDojo fields compared to version 1.

### Deduplication Algorithm
Default Deduplication Hashcode Fields:
By default, DefectDojo Parser V2 identifies duplicate findings using the following [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- vuln_id_from_tool
- endpoints

The legacy version (version 1) uses the legacy deduplication algorithm.

### CSV and XML differences and similarityies
The parser attempts to parse XML and CSV files in a similar way. However, this is not always possible. The following lists the differences between the parsers:

- EPSS scores and percentiles are only available in CSV format.
- CVSS vectors are only available in the XML format.
- The CVSS score will always be reported as CVSS v3 in the CSV parser 
- The references in the CSV parser will never contain URLs.

If no supported CVSS version is detected, the score (if present) is registered as a CVSS v3 score, even if this is incorrect.
