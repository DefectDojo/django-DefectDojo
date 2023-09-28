---
title: "Bandit"
toc_hide: true
---

### File Types
DefectDojo parser accepts a .json file.

To export a .json file from Bandit, you will need to install and run the .json report formatter to your Bandit instance.  
See Bandit documentation: https://bandit.readthedocs.io/en/latest/formatters/index.html


### Acceptable JSON Format
All properties are expected as strings, except "metrics" properties, which are expected as numbers.  All properties are required by the parser.

~~~
{
    "errors": [],
    "generated_at": "example-timestamp",
    "metrics": {
        "_totals": {
            "CONFIDENCE.HIGH": 1.0,
            "CONFIDENCE.LOW": 0.0,
            "CONFIDENCE.MEDIUM": 0.0,
            "CONFIDENCE.UNDEFINED": 0.0,
            "SEVERITY.HIGH": 0.0,
            "SEVERITY.LOW": 1.0,
            "SEVERITY.MEDIUM": 0.0,
            "SEVERITY.UNDEFINED": 0.0,
            "loc": 2,
            "nosec": 0
        },
            "one/one.py": {
                "CONFIDENCE.HIGH": 1.0,
                "CONFIDENCE.LOW": 0.0,
                "CONFIDENCE.MEDIUM": 0.0,
                "CONFIDENCE.UNDEFINED": 0.0,
                "SEVERITY.HIGH": 0.0,
                "SEVERITY.LOW": 1.0,
                "SEVERITY.MEDIUM": 0.0,
                "SEVERITY.UNDEFINED": 0.0,
                "loc": 2,
                "nosec": 0
            }
        ...
    },
    "results": [
            {
                "code": "1 import os\n2 assert False\n",
                "filename": "example.filename",
                "issue_confidence": "example_confidence",
                "issue_severity": "example_severity",
                "issue_text": "Example issue description.",
                "line_number": 2,
                "line_range": [
                    2
                ],
                "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b101_assert_used.html",
                "test_id": "B101",
                "test_name": "assert_used"
            }
        ...
    ]
}
~~~

### Sample Scan Data
Sample Bandit scans can be found at https://github.com/DefectDojo/sample-scan-files/tree/master/bandit.