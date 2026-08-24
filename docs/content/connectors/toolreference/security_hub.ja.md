---
title: "AWS Security Hub"
description: "DefectDojo で AWS Security Hub の Upstream Connector をセットアップする方法"
weight: 117
audience: pro
---
AWS Security Hub コネクタは、Security Hub の API とやり取りするために AWS アクセスキーを使用します。

#### Prerequisites

チームメンバーの AWS アクセスキーを使用するのではなく、DefectDojo 専用に AWS アカウント内で IAM ユーザーを作成し、そのユーザーの権限を Security Hub とのやり取りに必要な範囲に限定することをお勧めします。

AWS の「**[AWSSecurityHubReadOnlyAccess](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSSecurityHubReadOnlyAccess.html)** ポリシー」は、コネクタに必要なレベルのアクセスを提供します。Connector 用にカスタムポリシーを作成したい場合は、以下の権限を含める必要があります。

* [DescribeHub](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_DescribeHub.html)
* [GetFindingAggregator](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindingAggregator.html)
* [GetFindings](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindings.html)
* [ListFindingAggregators](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_ListFindingAggregators.html)

実際に機能するポリシー定義は、以下のようになります。

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

**ご注意ください:** 最良の利用体験を提供するため、今後追加の API アクションが必要になる場合があり、その際はこのポリシーの更新が必要になります。

IAM ユーザーを作成し、適切なポリシー/ロールを使って必要な権限を割り当てたら、アクセスキーを生成し、それを使って Connector を作成します。

#### Connector Mappings

1. **Location** フィールドに、[お使いのリージョンに対応する AWS API エンドポイント](https://docs.aws.amazon.com/general/latest/gr/sechub.html#sechub_region)を入力します。例えば `us-east-1` リージョンから結果を取得する場合は、以下を指定します。

`https://securityhub.us-east-1.amazonaws.com`
2. **Access Key** フィールドに有効な **AWS Access Key** を入力します。
3. **Secret Key** フィールドに対応する **Secret Key** を入力します。

DefectDojo は Security Hub の**クロスリージョン集約**機能を使って複数のリージョンから検出事項を取得できます。[クロスリージョン集約](https://docs.aws.amazon.com/securityhub/latest/userguide/finding-aggregation.html)が有効な場合は、「**Aggregation Region**」の API エンドポイントを指定してください。追加でリンクされているリージョンについては、AWS アカウント ID とリージョン名に基づいて DefectDojo 内に ProductRecords が作成されます。
