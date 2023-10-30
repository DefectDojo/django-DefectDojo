---
title: "Burp GraphQL"
toc_hide: true
---
Import the JSON data returned from the BurpSuite Enterprise GraphQL API. Append all the
issues returned to a list and save it as the value for the key "Issues". There is no need
to filter duplicates, the parser will automatically combine issues with the same name.

Example:

{{< highlight json >}}
{
    "Issues": [
        {
            "issue_type": {
                "name": "Cross-site scripting (reflected)",
                "description_html": "Issue Description",
                "remediation_html": "Issue Remediation",
                "vulnerability_classifications_html": "<li><a href=\"https://cwe.mitre.org/data/definitions/79.html\">CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')</a></li>",
                "references_html": "<li><a href=\"https://portswigger.net/web-security/cross-site-scripting\">Cross-site scripting</a></li>"
            },
            "description_html": "Details",
            "remediation_html": "Remediation Details",
            "severity": "high",
            "path": "/burp",
            "origin": "https://portswigger.net",
            "evidence": [
                {
                    "request_index": 0,
                    "request_segments": [
                        {
                            "data_html": "GET"
                        },
                        {
                            "highlight_html": "data"
                        },
                        {
                            "data_html": " HTTP More data"
                        }
                    ]
                },
                {
                    "response_index": 0,
                    "response_segments": [
                        {
                            "data_html": "HTTP/2 200 OK "
                        },
                        {
                            "highlight_html": "data"
                        },
                        {
                            "data_html": "More data"
                        }
                    ]
                }
            ]
        }
    ]
}
{{< /highlight >}}

Example GraphQL query to get issue details:

{{< highlight graphql >}}
    query Issue ($id: ID!, $serial_num: ID!) {
        issue(scan_id: $id, serial_number: $serial_num) {
            issue_type {
                name
                description_html
                remediation_html
                vulnerability_classifications_html
                references_html
            }
            description_html
            remediation_html
            severity
            path
            origin
            evidence {
                ... on Request {
                    request_index
                    request_segments {
                        ... on DataSegment {
                            data_html
                        }
                        ... on HighlightSegment {
                                highlight_html
                        }
                    }
                }
                ... on Response {
                    response_index
                    response_segments {
                        ... on DataSegment {
                            data_html
                        }
                        ... on HighlightSegment {
                            highlight_html
                        }
                    }
                }
            }
        }
    }
{{< /highlight >}}

