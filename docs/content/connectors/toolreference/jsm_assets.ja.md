---
title: "Jira Service Management Assets"
description: "DefectDojo で Jira Service Management Assets の Upstream Connector をセットアップする方法"
weight: 83
audience: pro
---
JSM Assetsコネクタは**Asset Connector**です。お使いのJira Service Management Assets(旧Insight)ワークスペース内のオブジェクトを列挙し、それぞれのオブジェクトに対してDefectDojoのAssetを作成します。オブジェクトスキーマごとにOrganizationsにグループ化されます。検出事項はインポートされません。

#### Prerequisites

* AssetsはJira Service Managementの**PremiumまたはEnterprise**プランが必要です。FreeまたはStandardプランでは、サイトの他の部分は動作していても、Assets APIは`403 "Access to Assets API was denied"`を返します。
* トークンに紐づくAtlassianアカウントは、そのサイトで**Jira Service Managementの製品アクセス権**(エージェントシート)を持っている必要があります。サイトへのアクセスだけでは不十分です。
* [id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens)でクラシックなAtlassian APIトークンを作成します。専用のサービスアカウントの使用をお勧めします。

#### Connector Mappings

1. **Location**フィールドにAtlassianサイトのURLを入力します: `https://{your-site}.atlassian.net`。
2. **Email**フィールドに、トークンが属するAtlassianアカウントのメールアドレスを入力します。
3. **Secret**フィールドにAPIトークンを入力します。

各AssetsオブジェクトはオブジェクトのラベルにちなんだRecordとなり、その**object schema**でグループ化されます。
