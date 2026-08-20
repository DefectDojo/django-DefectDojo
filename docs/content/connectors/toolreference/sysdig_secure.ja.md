---
title: "Sysdig Secure"
description: "DefectDojo で Sysdig Secure の Upstream Connector をセットアップする方法"
weight: 130
audience: pro
---
Sysdig Secure コネクタは、Sysdig Secure の脆弱性管理 API から**コンテナ / CNAPP 脆弱性検出事項**をインポートします。設定されたスコープ全体でアカウント全体を同期し、スキャン対象のアセットグループごとに DefectDojo 製品を作成します。

#### Prerequisites

Sysdig Secure の **API トークン**: Sysdig Secure で **Settings > Sysdig Secure API Token** に移動し、トークンをコピーします。また、Sysdig の**リージョン URL**(例: `https://us2.app.sysdig.com`、`https://eu1.app.sysdig.com`、またはオンプレミスホスト)も必要です。

#### Connector Mappings

1. **Location** フィールドに Sysdig のリージョン / ベース URL を入力します。
2. **Secret** フィールドに API トークンを入力します。
3. 必要に応じて **Scopes** を設定します — `runtime`、`registry`、`pipeline` のカンマ区切りリストです(空欄の場合はデプロイ済みワークロードのスコープである `runtime` になります)。
4. 必要に応じて **Runtime Product Grouping** を設定します — ランタイムの結果を製品にどうマッピングするか(`cluster`、`namespace`、`workload`、`image`)を指定します(空欄の場合は `namespace` になります)。レジストリおよびパイプラインの結果は常にイメージリポジトリ単位でグループ化されます。
5. 必要に応じて、**Minimum Severity** を設定してインポートする検出事項を絞り込みます。

各アセットグループは Record になります。各スキャン結果について、コネクタは脆弱性のあるすべてのパッケージを検出事項としてインポートします。**Runtime** の検出事項(デプロイ済みワークロード)は動的検出事項として記録され、Kubernetes のクラスター / 名前空間 / ワークロード / コンテナのコンテキストがタグ付けされます。**registry** および **pipeline** の検出事項は静的なイメージスキャン検出事項として記録されます。Sysdig の `NEGLIGIBLE` 深刻度は Info にマッピングされます。
