---
title: "AWS Prowler V3"
toc_hide: true
---

### File Types
DefectDojo parser accepts a .json-ocsf file. Please note: earlier versions of AWS Prowler create output data in a different format. See our other documentation if you are using an earlier version of AWS Prowler: 
* [Prowler v2](https://documentation.defectdojo.com/integrations/parsers/file/aws_prowler/) 
* [Prowler v3](https://documentation.defectdojo.com/integrations/parsers/file/aws_prowler_v3/) 

JSON reports can be created from the [AWS Prowler V4 CLI](https://docs.prowler.cloud/en/latest/tutorials/reporting/#json) using the following command: `prowler <provider> -M json-ocsf`

### Acceptable JSON Format
The parser expects an array of assessments. All properties are strings and are required by the parser.

~~~

[{
    "metadata": {
        "event_code": "iam_role_administratoraccess_policy_permissive_trust_relationship",
        "product": {
            "name": "Prowler",
            "vendor_name": "Prowler",
            "version": "4.2.1"
        },
        "version": "1.2.0"
    },
    "severity_id": 4,
    "severity": "High",
    "status": "Suppressed",
    "status_code": "FAIL",
    "status_detail": "IAM Role myAdministratorExecutionRole has AdministratorAccess policy attached that has too permissive trust relationship.",
    "status_id": 3,
    "unmapped": {
        "check_type": "",
        "related_url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_job-functions.html#jf_administrator",
        "categories": "trustboundaries",
        "depends_on": "",
        "related_to": "",
        "notes": "CAF Security Epic: IAM",
        "compliance": {}
    },
    "activity_name": "Create",
    "activity_id": 1,
    "finding_info": {
        "created_time": "2024-06-03T14:15:19.382075",
        "desc": "Ensure IAM Roles with attached AdministratorAccess policy have a well defined trust relationship",
        "product_uid": "prowler",
        "title": "Ensure IAM Roles with attached AdministratorAccess policy have a well defined trust relationship",
        "uid": "prowler-aws-iam_role_administratoraccess_policy_permissive_trust_relationship-123456789012-us-east-1-myAdministratorExecutionRole"
    },
    "resources": [
        {
            "cloud_partition": "aws",
            "region": "us-east-1",
            "data": {
                "details": ""
            },
            "group": {
                "name": "iam"
            },
            "labels": [],
            "name": "myAdministratorExecutionRole",
            "type": "AwsIamRole",
            "uid": "arn:aws:iam::123456789012:role/myAdministratorExecutionRole"
        }
    ],
    "category_name": "Findings",
    "category_uid": 2,
    "class_name": "DetectionFinding",
    "class_uid": 2004,
    "cloud": {
        "account": {
            "name": "",
            "type": "AWS_Account",
            "type_id": 10,
            "uid": "123456789012",
            "labels": []
        },
        "org": {
            "name": "",
            "uid": ""
        },
        "provider": "aws",
        "region": "us-east-1"
    },
    "event_time": "2024-06-03T14:15:19.382075",
    "remediation": {
        "desc": "Apply the principle of least privilege. Instead of AdministratorAccess, assign only the permissions necessary for specific roles and tasks. Create custom IAM policies with minimal permissions based on the principle of least privilege. If a role really needs AdministratorAccess, the trust relationship must be well defined to restrict it usage only to the Principal, Action, Audience and Subject intended for it.",
        "references": [
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"
        ]
    },
    "risk_details": "The AWS-managed AdministratorAccess policy grants all actions for all AWS services and for all resources in the account and as such exposes the customer to a significant data leakage threat. It is therefore particularly important that the trust relationship is well defined to restrict it usage only to the Principal, Action, Audience and Subject intended for it.",
    "type_uid": 200401,
    "type_name": "Create"
}]

~~~

### Sample Scan Data
Unit tests of AWS Prowler V4 JSON-OCSF can be found at https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/aws_prowler_v4.