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
