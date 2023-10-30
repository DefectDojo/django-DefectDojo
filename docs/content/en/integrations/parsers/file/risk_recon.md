---
title: "Risk Recon API Importer"
toc_hide: true
---
Import findings from Risk Recon via the API. Configure your own JSON report as follows

{{< highlight json >}}
{
    "url_endpoint": "https://api.riskrecon.com/v1",
    "api_key": "you-api-key",
    "companies": [
        {
            "name": "Company 1",
            "filters": {
                "domain_name": [],
                "ip_address": ["127.0.0.1"],
                "host_name": ["localhost"],
                "asset_value": [],
                "severity": ["critical", "high"],
                "priority": [],
                "hosting_provider": [],
                "country_name": []
            }
        },
        {
            "name": "Company 2",
            "filters": {
                "ip_address": ["0.0.0.0"]
            }
        }

    ],
    "filters": {
        "domain_name": [],
        "ip_address": [],
        "host_name": [],
        "asset_value": [],
        "severity": ["critical"],
        "priority": [],
        "hosting_provider": [],
        "country_name": []
    }
}
{{< /highlight >}}

-   More than one company finding list can be queried with it\'s own set
    of filters. Company 1 shows all available fitlers, while Company 2
    shows that empty filters need not be present.
-   To query all companies in your Risk Recon instance, simple remove
    the \"companies\" field entirely.
-   If the \"companies\" field is not present, and filtering is still
    requested, the \"filters\" field can be used to filter all findings
    across all companies. It carries the same behavior as the company
    filters. The \"filters\" field is disregarded in the prescense of
    the \"companies\" field.
-   Removing both fields will allow retrieval of all findings in the
    Risk Recon instance.
