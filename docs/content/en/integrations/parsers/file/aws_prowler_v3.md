---
title: "AWS Prowler V3"
toc_hide: true
---

### File Types
DefectDojo parser accepts a .json file.  Please note: earlier versions of AWS Prowler create output data in a different format.  See our other documentation if you are using an earlier version of AWS Prowler: https://documentation.defectdojo.com/integrations/parsers/file/aws_prowler/

JSON reports can be created from the [AWS Prowler V3 CLI](https://docs.prowler.cloud/en/latest/tutorials/reporting/#json) using the following command: `prowler <provider> -M json`

### Acceptable JSON Format
Parser expects an array of assessments.  All properties are strings and are required by the parser.

~~~

[
        {
            "AssessmentStartTime": "example_timestamp",
            "FindingUniqueId": "example_uniqueIdFromTool",
            "Provider": "example_provider",
            "CheckID": "acm_certificates_expiration_check",
            "CheckTitle": "Check if ACM Certificates are about to expire in specific days or less",
            "CheckType": [
                "Example ASFF-Compliant Finding Type"
            ],
            "ServiceName": "example_awsServiceName",
            "SubServiceName": "",
            "Status": "FAIL",
            "StatusExtended": "Example status description",
            "Severity": "example_severity",
            "ResourceType": "AwsCertificateManagerCertificate",
            "ResourceDetails": "",
            "Description": "Example general test description.",
            "Risk": "Example test impact description.",
            "RelatedUrl": "https://docs.aws.amazon.com/config/latest/developerguide/acm-certificate-expiration-check.html",
            "Remediation": {
                "Code": {
                    "NativeIaC": "",
                    "Terraform": "",
                    "CLI": "",
                    "Other": ""
                },
                "Recommendation": {
                    "Text": "Example recommendation.",
                    "Url": "https://docs.aws.amazon.com/config/latest/developerguide/example_related_documentation.html"
                }
            },
            "Compliance": {
                    "GDPR": [
                        "article_32"
                    ],
                ...
            },
            "Categories": [],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "",
            "Profile": null,
            "AccountId": "example_accountId",
            "OrganizationsInfo": null,
            "Region": "example_region",
            "ResourceId": "example.resource.id.com",
            "ResourceArn": "arn:aws:acm:us-east-1:999999999999:certificate/ffffffff-0000-0000-0000-000000000000",
            "ResourceTags": {}
        }
    ...
]

~~~

### Sample Scan Data
Unit tests of AWS Prowler V3 JSON can be found at https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/aws_prowler_v3.