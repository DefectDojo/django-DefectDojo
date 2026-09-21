---
title: "Azure DevOps Boards"
description: "DefectDojo で Azure DevOps Boards のダウンストリームコネクタをセットアップする方法"
weight: 21
audience: pro
---
### Instance Setup

- **Label** は、この統合を識別するために使用したいラベルを設定します。
- **Location** は、Azure の URL を設定します。例: `https://dev.azure.com/{your organization}`
- **Token** は、Azure のパーソナルアクセストークンを設定します。

Azure DevOps での認証には、作業対象の Azure プロジェクトの「Work Items」に対して「Read, Write and Manage」権限を持つ[パーソナルアクセストークン](https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate?view=azure-devops&tabs=Windows)が必要です。

### Issue Tracker Mapping

これらの項目は、DefectDojo が Finding または Finding Group の属性を Azure DevOps の該当プロジェクトにどのようにマッピングするかを指定します。

#### Issue Tracker Mapping Details

`Project ID` フィールドには、Azure における対象プロジェクトの名前または ID を指定します。

#### Severity Mapping Details

フォームの各項目にはデフォルト値が設定されており、内容は以下のとおりです。

- **Severity Field Name**: `/fields/Microsoft.VSTS.Common.Priority`
- **Info Mapping**: `4`
- **Low Mapping**: `4`
- **Medium Mapping**: `3`
- **High Mapping**: `2`
- **Critical Mapping**: `1`

#### Status Mapping Details

フォームの各項目にはデフォルト値が設定されており、内容は以下のとおりです。

- **Status Field Name**: `/fields/System.State`
- **Active Mapping**: `To Do`
- **Closed Mapping**: `Done`
- **False Positive Mapping**: `Done`
- **Risk Accepted Mapping**: `Done`
