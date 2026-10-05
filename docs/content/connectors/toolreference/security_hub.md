---
title: "Security Hub"
description: "How to set up the Security Hub Upstream Connector for DefectDojo"
weight: 117
audience: pro
---
The AWS Security Hub connector uses an AWS access key to interact with the Security Hub APIs.

#### Prerequisites

Rather than use the AWS access key from a team member, we recommend creating an IAM User in your AWS account specifically for DefectDojo, with that user's permissions limited to those necessary for interacting with Security Hub.

AWS's "**[AWSSecurityHubReadOnlyAccess](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSSecurityHubReadOnlyAccess.html)**policy" provides the required level of access for a connector. If you would like to write a custom policy for a Connector, you will need to include the following permissions:

* [DescribeHub](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_DescribeHub.html)
* [GetFindingAggregator](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindingAggregator.html)
* [GetFindings](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindings.html)
* [ListFindingAggregators](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_ListFindingAggregators.html)

A working policy definition might look like the following:

```
{  
    "Version": "2012-10-17",  
    "Statement": [  
        {  
            "Sid": "AWSSecurityHubConnectorPerms",  
            "Effect": "Allow",  
            "Action": [  
                "securityhub:DescribeHub",  
                "securityhub:GetFindingAggregator",  
                "securityhub:GetFindings",  
                "securityhub:ListFindingAggregators"  
            ],  
            "Resource": "*"  
        }  
    ]  
}
```

**Please note:** we may need to use additional API actions in the future to provide the best possible experience, which will require updates to this policy.

Once you have created your IAM user and assigned it the necessary permissions using an appropriate policy/role, you will need to generate an access key, which you can then use to create a Connector.

#### Connector Mappings

1. Enter the appropriate [AWS API Endpoint for your region](https://docs.aws.amazon.com/general/latest/gr/sechub.html#sechub_region) in the **Location** field**:**  for example, to retrieve results from the `us-east-1` region, you would supply

`https://securityhub.us-east-1.amazonaws.com`
2. Enter a valid **AWS Access Key** in the **Access Key** field.
3. Enter a matching **Secret Key** in the **Secret Key** field.

DefectDojo can pull Findings from more than one region using Security Hub's **cross\-region aggregation** feature. If [cross\-region aggregation](https://docs.aws.amazon.com/securityhub/latest/userguide/finding-aggregation.html) is enabled, you should supply the API endpoint for your "**Aggregation Region**". Additional linked regions will have ProductRecords created for them in DefectDojo based on your AWS account ID and the region name.

#### Asset Grouping (optional)

By default the connector creates one Record, and so one asset, per AWS account and region, named `Account <account id> (<region>)`. Every finding in that account and region lands on that one asset, whatever resource it is about. The **Asset Grouping** field, under **Import Filters** on the connector form, can split findings more finely:

| Asset Grouping | Records | Findings are imported on |
|---|---|---|
| **Account and Region** (default) | one per AWS account and region | the account and region Records |
| **Resource type** | additionally, one per resource type (EC2, ECR, Lambda, S3, ...) under each account and region | the resource type Records |
| **Resource** | additionally, one per resource, under its resource type | the resource Records |

With **Resource**, a container image is not a resource of its own: every image of an ECR repository is grouped under that repository, along with the repository's own findings, because an image digest is a version of the repository. Lambda function versions are likewise grouped under the function.

Resource Records are named `<resource> (<type>, <account>, <region>)`, for example `team/api (ECR, prod / 111111111111, us-east-1)` or `web-1 [i-0abc] (EC2, prod / 111111111111, us-east-1)`. The account ID is always part of the name; the account name is added when DefectDojo can read it (see *Optional permission* below).

With a finer grouping:

* The account and region Records keep the same identity and become **parent assets**. They carry no findings themselves. When the Asset Hierarchy feature is enabled, DefectDojo relates each resource type asset to its account and region asset, and each resource asset to its resource type asset, with a `parent` relationship. Findings then roll up the hierarchy. Relationships created by the connector never overwrite relationships you created by hand.
* Each finding is imported once, on the asset of the first resource it names (Security Hub lists the affected resource first). The total number of findings is the same under every grouping.
* Resources are discovered from findings, so only resources with at least one finding that the connector would import (active, at or above the minimum severity, from an AWS service) become Records. A resource whose last finding is fixed keeps its Record for 14 days so that the next Syncs close its findings in DefectDojo, after which the Record is marked MISSING.
* AWS resource tags reach resource assets as asset tags, prefixed `aws:` (for example `aws:team:payments`). Tags you add yourself are never touched; tags that start with `aws:` on resource assets are managed by the connector.
* The connector makes one Security Hub request per Record on each Sync, paced below the Security Hub API rate limit, so a Sync with thousands of resource Records takes longer than an account and region Sync. Memory use stays low because findings are processed one page at a time.

**Switching an existing connection to a finer grouping:** the field can be changed at any time. On the next discovery, the new Records appear for mapping; enable **Auto Map** on the connection when you change the grouping so findings move without a gap. On the next Sync, the account and region assets stop receiving findings and their previously imported findings are closed (the same findings are imported again on the new assets, with fresh status). Notes and history on the old findings stay on the account and region assets. Switching back reverses this: the account and region Records carry findings again (previously closed findings re-open as they re-match), and the finer Records close their findings and are then marked MISSING. Their assets are kept, so you can archive them at your convenience.

#### Organization Placement (optional)

New assets from a Security Hub connection are placed in the organization named **Security Hub Connector**. The **Organization Placement** field can instead place each AWS account's assets in an organization of its own:

* **One per AWS account, named by account ID:** organizations named `AWS <account id>`.
* **One per AWS account, named by account name:** organizations named after the AWS account name, falling back to `AWS <account id>` when the name cannot be read.

Organizations are created when they do not exist yet, and reused when they do. The field only affects assets created after it is set: assets that already exist are never moved.

#### Optional permission: AWS account names

To show AWS account names in Record names and to name organizations after accounts, the connector reads the account list from AWS Organizations, which needs the `organizations:ListAccounts` permission. Only the AWS Organizations management account or a delegated administrator account can grant it. Without it, the connector uses account IDs and nothing else changes. The connector only asks for account names when the grouping is finer than the default or when **Organization Placement** uses account names.

```
{
    "Sid": "AWSSecurityHubConnectorAccountNames",
    "Effect": "Allow",
    "Action": "organizations:ListAccounts",
    "Resource": "*"
}
```
