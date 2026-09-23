---
title: "GitHub Advanced Security"
description: "DefectDojo で GitHub Advanced Security の Upstream Connector をセットアップする方法"
weight: 64
audience: pro
---
GitHub Advanced Securityコネクタは、GitHubから**code scanning**、**Dependabot**、**secret scanning**のアラートを、3つの独立した検出事項タイプ（`GitHub:CodeScanning`、`GitHub:Dependabot`、`GitHub:SecretScanning`）としてインポートします。DefectDojoは、設定した組織内のアーカイブされていないすべてのリポジトリを検出し、それぞれについてレコードを作成します。

#### Prerequisites

インポートしたいリポジトリでは、GitHub Advanced Security機能が有効になっている必要があります。コネクタはGitHubの**個人アクセストークン**で認証を行います。

1. GitHubで**Settings > Developer settings > Personal access tokens**を開き、対象の組織が所有する（またはアクセス権を持つ）トークンを作成します。
2. セキュリティアラートへの読み取りアクセス権を付与します。*fine-grained*トークンの場合、組織のリポジトリに対して**Code scanning alerts**、**Dependabot alerts**、**Secret scanning alerts**への**Read-only**アクセスが必要です。*classic*トークンの場合は**`repo`**と**`security_events`**のスコープが必要です。
3. トークンのownerがインポート対象のリポジトリを参照できることを確認してください。コネクタは、トークンがアクセスできるリポジトリしか参照できません。

#### Connector Mappings

1. **Location**フィールドに`https://api.github.com`を入力します。GitHub Enterprise Serverの場合は`https://<your-host>/api/v3`を使用してください。
2. **Organization**フィールドに組織のログイン名を入力します。
3. **Secret**フィールドに個人アクセストークンを入力します。
4. 必要に応じて、インポートする検出事項を制限するために**Minimum Severity**を設定します。

アーカイブされていない各リポジトリはレコードとなり、3種類のアラートファミリーそれぞれについてオープンなアラートが照会されます。あるリポジトリで特定のアラートファミリーが有効になっていない場合、それはresolvedとして報告されるのではなくスキップされるため、無効化された機能によって誤ってクローズされることはありません。
