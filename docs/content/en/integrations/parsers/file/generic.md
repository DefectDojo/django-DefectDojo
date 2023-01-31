---
title: "Generic Findings Import"
toc_hide: true
---
Import Generic findings in CSV or JSON format.

Attributes supported for CSV:
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

The CSV expects a header row with the names of the attributes.

Example of JSON format:

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
            "file_path": "src/first.cpp",
            "line": 13,
            "endpoints": [
                {
                    "host": "exemple.com"
                }
            ]
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
