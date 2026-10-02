---
title: "Azure DevOps"
description: "DefectDojo で Azure DevOps の Upstream Connector をセットアップする方法"
weight: 20
audience: pro
---
Azure DevOps コネクタは**Asset Connector**です。Azure DevOps 組織内のすべてのプロジェクトにある git リポジトリを列挙し、リポジトリごとに DefectDojo のアセットを作成し、Azure DevOps のプロジェクト単位で組織にグループ化します。検出事項はインポートされません。

#### Prerequisites

組織用の Personal Access Token(PAT)が必要です。専用のサービスアカウントからトークンを作成することをお勧めします。必要なのは読み取りスコープのみです。

1. Azure DevOps で **User settings \> Personal access tokens \> New Token** を開きます。
2. **Show all scopes** をクリックし、**Code: Read** と **Project and Team: Read** を選択します。

対応しているのは Azure DevOps Services(dev.azure.com)のみです。オンプレミスの Azure DevOps Server には現時点で対応していません。

#### Connector Mappings

1. **Location** フィールドに組織の URL を入力します: `https://dev.azure.com/{your-organization}`。従来の `https://{your-organization}.visualstudio.com` 形式の URL も受け付けられ、余分なパスセグメント(例えば特定プロジェクトへのリンク)は無視されます。
2. **Secret** フィールドに PAT を入力します。

各リポジトリは、そのリポジトリ名を冠したレコードとなり、Azure DevOps の**プロジェクト**単位でグループ化されます。無効化されたリポジトリはスキップされるため、リポジトリを無効化または削除すると、次の Sync でそのレコードは `MISSING` としてフラグされます。
