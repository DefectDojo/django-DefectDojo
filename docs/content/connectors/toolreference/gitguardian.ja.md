---
title: "GitGuardian"
description: "DefectDojo で GitGuardian の Upstream Connector をセットアップする方法"
weight: 62
audience: pro
---
GitGuardianコネクタは、GitGuardian REST APIを使用して**secret incident**（GitGuardianが監視対象のソース全体で検出した、漏えいした認証情報）をインポートします。DefectDojoは、現在オープンなincidentを持つ監視対象ソース（リポジトリまたはperimeter）ごとにレコードを作成し、オープンな各incidentを検出事項としてインポートします。

セキュリティ上の理由から、コネクタがインポートするのはincidentの**メタデータ**（detector、深刻度、validity、status、GitGuardianへのリンク）のみです。漏えいしたsecretの値そのものがDefectDojoによって取得・保存されることはありません。影響を受けた箇所を確認するには、各検出事項に含まれるリンクからGitGuardianを参照してください。

#### Prerequisites

GitGuardianのAPIキーが必要です。自動化された操作を区別しやすくするため、個人アクセストークンではなく**Service Accountトークン**を使用することをお勧めします。GitGuardianダッシュボードの**API**でトークンを作成し、以下の読み取りスコープを付与してください。

* `incidents:read`
* `sources:read`

#### Connector Mappings

1. **Location**フィールドにGitGuardianのAPI URLを入力します。SaaSプラットフォームの場合は`https://api.gitguardian.com`、自己ホスト型インスタンスの場合はそのAPI URLを入力します。
2. **Secret**フィールドにAPIキーを入力します。

インポートされるのは**open**なincident（statusが`TRIGGERED`または`ASSIGNED`のもの）のみです。GitGuardian側でresolveまたはignoreにしたincidentは、次回の同期時にDefectDojo側でも自動的に緩和済みになります。有効性が確認済みのsecret（validityが*valid*）は、検証済みの検出事項としてインポートされます。
