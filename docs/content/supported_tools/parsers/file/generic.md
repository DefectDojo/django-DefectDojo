---
title: 'Generic Findings Import'
toc_hide: true
---

Generic Findings Import can be used to import any report in CSV or JSON format.

### Supported Attributes (CSV)

- Date: Date of the finding in mm/dd/yyyy format.
- Title: Title of the finding
- CweId: Cwe identifier, must be an integer value.
- Url: Url associated with the finding.
- Severity: Severity of the finding. Must be one of Info, Low, Medium, High, or Critical.
- Description: Description of the finding. Can be multiple lines if enclosed in double quotes.
- Mitigation: Possible Mitigations for the finding. Can be multiple lines if enclosed in double quotes.
- Impact: Detailed impact of the finding. Can be multiple lines if enclosed in double quotes.
- References: References associated with the finding. Can be multiple lines if enclosed in double quotes.
- Active: Indicator if the finding is active. Must be empty, TRUE or FALSE
- Verified: Indicator if the finding has been verified. Must be empty, TRUE, or FALSE
- FalsePositive: Indicator if the finding is a false positive. Must be TRUE, or FALSE.
- Duplicate:Indicator if the finding is a duplicate. Must be TRUE, or FALSE
- IsMitigated: Indicator if the finding is mitigated. Must be TRUE, or FALSE
- MitigatedDate: Date the finding was mitigated in mm/dd/yyyy format or ISO format
- epss_score: Finding [EPSS score](https://www.first.org/epss/)
- epss_percentile: Finding [EPSS percentile](https://www.first.org/epss/articles/prob_percentile_bins)
- CVSSV3: CVSSv3 verctor of the finding
- CVSSV3_score: CVSSv3 score of the finding
- CVSSV4: CVSSv4 vector of the finding
- CVSSV4_score: CVSSv4 score of the finding
- known_exploited: Indicator if the finding is listed in Known Exploited List. Must be TRUE, or FALSE
- ransomware_used: Indicator if the finding is used in Ransomware. Must be TRUE, or FALSE
- fix_available: Indicator if fix available for the finding. Must be TRUE, or FALSE
- kev_date: Date the finding was added to Known Exploited Vulnerabilities list in mm/dd/yyyy format or ISO format.

The CSV expects a header row with the names of the attributes.

Date fields are parsed using [dateutil.parse](https://dateutil.readthedocs.io/en/stable/parser.html) supporting a variety of formats such a YYYY-MM-DD or ISO-8601.

### Supported Attributes (JSON)

The list of supported fields in JSON format:

- title: **Required.** String
- severity: **Required.** One of the "Critical", "High", "Medium", "Low", "Info"
- description: **Required.** String
- date: Date
- cwe: Int
- cve: String
- epss_score: Float
- epss_percentile: Float
- cvssv3: String
- cvssv3_score: Float
- cvssv4: String
- cvssv4_score: Float
- mitigation: String
- impact: String
- steps_to_reproduce: String
- severity_justification: String
- references: String
- active: Bool
- verified: Bool
- false_p: Bool
- out_of_scope: Bool
- risk_accepted: Bool
- under_review: Bool
- is_mitigated: Bool
- thread_id: String
- mitigated: Bool
- numerical_severity: Int
- param: String
- payload: String
- line: Int
- file_path: String
- component_name: String
- component_version: String
- static_finding: Bool
- dynamic_finding: Bool
- scanner_confidence: Int
- unique_id_from_tool: String
- vuln_id_from_tool: String
- sast_source_object: String
- sast_sink_object: String
- sast_source_line: Int
- sast_source_file_path: String
- nb_occurences: Int
- publish_date: Date
- service: String
- planned_remediation_date: Date
- planned_remediation_version: String
- effort_for_fixing: One of the "High", "Medium", "Low"
- tags: List of Strings
- kev_date: Date
- known_exploited: Bool
- ransomware_used: Bool
- fix_available: Bool

### Example JSON

```JSON
{
    "findings": [
        {
            "title": "test title with endpoints as dict",
            "description": "Some very long description with\n\n some UTF-8 chars à qu'il est beau",
            "severity": "Medium",
            "mitigation": "Some mitigation",
            "date": "2021-01-06",
            "cve": "CVE-2020-36234",
            "cwe": 261,
            "cvssv3": "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N",
            "cvssv4": "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
            "cvssv4_score": 7.3,
            "known_exploited": true,
            "ransomware_used": true,
            "fix_available": true,
            "kev_date": "2024-05-01",
            "file_path": "src/first.cpp",
            "line": 13,
            "endpoints": [
                {
                    "host": "exemple.com"
                }
            ],
            "tags": [
                "security",
                "myTag"
            ],
        },
        {
            "title": "test title with endpoints as strings",
            "description": "Some very long description with\n\n some UTF-8 chars à qu'il est beau2",
            "severity": "Critical",
            "mitigation": "Some mitigation",
            "date": "2021-01-06",
            "cve": "CVE-2020-36235",
            "cwe": 287,
            "cvssv3": "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N",
            "file_path": "src/two.cpp",
            "line": 135,
            "endpoints": [
                "http://urlfiltering.paloaltonetworks.com/test-command-and-control",
                "https://urlfiltering.paloaltonetworks.com:2345/test-pest"
            ]
        },
        {
            "title": "test title",
            "description": "Some very long description with\n\n some UTF-8 chars à qu'il est beau2",
            "severity": "Critical",
            "mitigation": "Some mitigation",
            "date": "2021-01-06",
            "cve": "CVE-2020-36236",
            "cwe": 287,
            "cvssv3": "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N",
            "file_path": "src/threeeeeeeeee.cpp",
            "line": 1353
        },
        {
            "title": "test title mitigated",
            "description": "Some very long description with\n\n some UTF-8 chars à qu'il est beau2",
            "severity": "Critical",
            "mitigation": "Some mitigation",
            "date": "2021-01-06",
            "cve": "CVE-2020-36236",
            "cwe": 287,
            "cvssv3": "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N",
            "file_path": "src/threeeeeeeeee.cpp",
            "line": 1353,
            "is_mitigated": true,
            "mitigated": "2021-01-16"
        },
        {
            "title": "test title mitigated ISO",
            "description": "Some very long description with\n\n some UTF-8 chars à qu'il est beau2",
            "severity": "Critical",
            "mitigation": "Some mitigation",
            "date": "2024-01-04T11:02:11Z",
            "cve": "CVE-2020-36236",
            "cwe": 287,
            "cvssv3": "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N",
            "file_path": "src/threeeeeeeeee.cpp",
            "line": 1353,
            "is_mitigated": true,
            "mitigated": "2024-01-24T11:02:11Z"
        }
    ]
}
```

This parser supports an attributes that accept files as Base64 strings. These files are attached to the respective findings.

Example:

```JSON
{
    "name": "My wonderful report",
    "findings": [
        {
            "title": "Vuln with image",
            "description": "Some very long description",
            "severity": "Medium",
            "files": [
                {
                    "title": "Screenshot from 2017-04-10 16-54-19.png",
                    "data": "iVBORw0KGgoAAAANSUhEUgAABWgAAAK0CAIAAAARSkPJAAAAA3N<...>TkSuQmCC"
                }
            ]
        }
    ]
}
```

This parser supports an attribute `name` and `type` to be able to define `TestType`. Based on this, you can define custom `HASHCODE_FIELDS` or `DEDUPLICATION_ALGORITHM` in the settings.

Example:

```JSON
{
    "name": "My wonderful report",
    "type": "My custom Test type",
    "findings": [
    ]
}
```

### Sample Scan Data

Sample Generic Findings Import scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/generic).

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- cwe
- line
- file path
- description
