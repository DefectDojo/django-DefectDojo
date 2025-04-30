---
title: "Generic Findings Import"
toc_hide: true
weight: 2
---

You can use Generic Findings Import as a method to ingest JSON or CSV files into DefectDojo which are not already in the supported parsers list.

Files uploaded using Generic Findings Import must conform to the accepted format with respect to CSV column headers / JSON attributes.

These attributes are supported for CSV:

- Date: Date of the finding in mm/dd/yyyy format.
- Title: Title of the finding
- CweId: Cwe identifier, must be an integer value.
- epss_score: The probability of exploitation in the next 30 days, must be a float value between 0 and 1.0.
- epss_percentile: The proportion of all scored vulnerabilities with the same or a lower EPSS score, must be a float value between 0 and 1.0.
- Url: Url associated with the finding.
- Severity: Severity of the finding. Must be one of Info, Low, Medium, High, or Critical.
- Description: Description of the finding. Can be multiple lines if enclosed in double quotes.
- Mitigation: Possible Mitigations for the finding. Can be multiple lines if enclosed in double quotes.
- Impact: Detailed impact of the finding. Can be multiple lines if enclosed in double quotes.
- References: References associated with the finding. Can be multiple lines if enclosed in double quotes.
- Active: Indicator if the finding is active. Must be empty, TRUE or FALSE
- Verified: Indicator if the finding has been verified. Must be empty, TRUE, or FALSE
- FalsePositive: Indicator if the finding is a false positive. Must be TRUE, or FALSE.
- Duplicate: Indicator if the finding is a duplicate. Must be TRUE, or FALSE

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

This parser supports some additional attributes to be able to define custom `TestTypes` as well as influencing some meta fields on the `Test`:

- `name`: The internal name of the tool you are using. This is primarily informational, and used for reading the report manually.
- `type`: The name of the test type to create in DefectDojo, with the suffix of `(Generic Findings Import)`. The suffix is an important identifier for future users attempting to identify the test type to supply when importing new reports. This value is very important to fetching the correct test type to import findings into, so be sure to keep the `type` consistent from import to import! As an example, a report submitted with a `type` of `Internal Company Tool` will produce a test type in DefectDojo with the title `Internal Company Tool (Generic Findings Import)`. With this newly created test type, you can define custom `HASHCODE_FIELDS` or `DEDUPLICATION_ALGORITHM` in the settings.
- `version`: The version of the tool you are using. This is primarily informational, and used for reading the report manually, and tracking format changes from version to version.
- `description`: A brief description of the test. This could be an explanation of what the tool is reporting, where the tools is maintained, who the point of contact is for the tool, or anything you like.
- `static_tool`: Dictates that tool used is running static analysis methods to discover vulnerabilities.
- `dynamic_tool`: Dictates that tool used is running dynamic analysis methods to discover vulnerabilities.
- `soc`: Dictates that tool is used for reporting alerts in a soc (Pro Edition Only).

Example:

```JSON
{
    "name": "My wonderful report",
    "type": "My custom Test type",
    "version": "1.0.5",
    "description": "A unicorn tool that is capable of static analysis, dynamic analysis, and even capturing soc alerts!",
    "static_tool": true,
    "dynamic_tool": true,
    "soc": true,
    "findings": [
    ]
}
```

### Sample Scan Data

Sample Generic Findings Import scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/generic).