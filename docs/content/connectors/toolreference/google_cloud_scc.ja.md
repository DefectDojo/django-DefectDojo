---
title: "Google Cloud Security Command Center"
description: "DefectDojo で Google Cloud Security Command Center の Upstream Connector をセットアップする方法"
weight: 67
audience: pro
---
Google Cloud SCCコネクタは、Security Command Center v2 REST APIを使用して、Google Cloudのorganization、folder、またはprojectからアクティブなセキュリティの検出事項をインポートします。DefectDojoは、オープンな検出事項を持つGoogle Cloudの**project**ごとにレコードを作成します。

#### Prerequisites

組織でSecurity Command Centerが**有効化**されている必要があります（Standardティアは無料です）。次に、検出事項を一覧取得できるサービスアカウントと、そのJSONキーが必要です。

1. Google Cloudでサービスアカウントを作成します。DefectDojo専用のアカウントを作成することをお勧めします。
2. インポートしたいスコープ（organization、folder、またはproject）に対して、**Security Center Findings Viewer**ロール（`roles/securitycenter.findingsViewer`）を付与します。
3. そのサービスアカウントの**JSONキー**を作成してダウンロードします。

#### Connector Mappings

1. 標準以外のエンドポイントを使用しない限り、**Location**フィールドはデフォルトの`https://securitycenter.googleapis.com`のままにします。
2. **Parent Resource**フィールドに、インポート元のスコープを入力します: `organizations/{id}`、`folders/{id}`、または`projects/{id}`。
3. サービスアカウントの**JSONキー**ファイルの内容全体を**Service Account Key**フィールドに貼り付けます。
4. 必要に応じて、インポートする検出事項を制限するために**Minimum Severity**を設定します。

インポートされるのは`ACTIVE`かつミュートされていない検出事項のみです。そのため、SCCで非アクティブ化またはミュートした検出事項は、次回の同期時にDefectDojo側でも自動的に緩和済みになります。各検出事項が影響するGCPのprojectが、そのレコードになります。
