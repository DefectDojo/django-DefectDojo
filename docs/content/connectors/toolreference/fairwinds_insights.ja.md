---
title: "Fairwinds Insights"
description: "DefectDojo で Fairwinds Insights の Upstream Connector をセットアップする方法"
weight: 56
audience: pro
---
Fairwinds Insightsコネクタは、[Fairwinds Insights](https://insights.fairwinds.com) REST APIを使用して、組織全体の**Kubernetesセキュリティの検出事項**をインポートします。DefectDojoは、アクティブな**クラスタ**をすべて列挙してそれぞれについてレコードを作成し、そのクラスタのSecurity **アクションアイテム**（Polaris、Trivy、Kube-bench、OPA、その他のInsightsレポートに由来）を検出事項としてインポートします。クラスタごとの個別設定はありません。

#### Prerequisites

Fairwinds Insightsの**organization**名と**APIトークン**が必要です。トークンはInsightsアプリの**Organization Settings > Tokens**で作成します。`read_only`トークンで十分です。このトークンは組織単位のスコープを持ち、ベアラートークンとして送信されます。ログに記録されることはありません。

#### Connector Mappings

1. **Location**フィールドには`https://insights.fairwinds.com`が自動入力されます。この値をそのまま使用するか、Insightsのホストを明示的に入力してください。
2. Insightsの**Organization**名（ダッシュボードのURLに表示されるスラッグ）を入力します。
3. **Secret**フィールドにInsightsのAPIトークンを入力します。
4. 必要に応じて、インポートする検出事項を制限するために**Minimum Severity**を設定します。

DefectDojoは、アクティブな各**クラスタ**をレコードにマッピングし、Securityの各**アクションアイテム**を検出事項にマッピングします。深刻度はFairwindsの数値スコア（DefectDojoの情報〜重大にマッピング）に基づき、そのアイテムを生成したFairwindsのレポート（`polaris`、`trivy`、`kube-bench`など）がツールタグになり、影響を受けるKubernetesリソースとコンテナイメージが含まれ、CVE識別子があれば抽出されます。検出事項は静的検出事項として記録され、Fairwindsのアクションアイテムのidで重複排除されます。

詳細については、[Fairwinds Insights APIのドキュメント](https://insights.docs.fairwinds.com/technical-details/api/)を参照してください。
