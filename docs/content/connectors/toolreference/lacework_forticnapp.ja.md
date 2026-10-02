---
title: "Lacework / FortiCNAPP"
description: "DefectDojo で Lacework / FortiCNAPP の Upstream Connector をセットアップする方法"
weight: 86
audience: pro
---
Lacework / FortiCNAPPコネクタは、Lacework v2 APIを使用して、Laceworkアカウント全体の**ホストおよびコンテナの脆弱性**をインポートします。

#### Prerequisites

Laceworkの**APIキー**(APIキーIDとシークレット)が必要です。これはLaceworkコンソールの**Settings → API keys**で作成します。コネクタは同期のたびにこれらを短命のアクセストークンと交換します。キーID、シークレット、トークンはログに記録されません。

#### Connector Mappings

1. **Location**フィールドにLaceworkのアカウントURLを入力します — 例: `https://YOUR-ACCOUNT.lacework.net`(アカウント名のみでも受け付けられます)。
2. **API Key ID**と**API Secret**を入力します。
3. 必要に応じて**Minimum Severity**を設定し、インポートする検出事項を制限できます。

DefectDojoはLaceworkの**アカウント**をRecord(アカウント全体のスコープ)にマッピングします。各**container**と**host**の脆弱性はそれぞれ検出事項になります。深刻度はLacework独自の評価から取得され、影響を受けるパッケージとバージョンがcomponentになり、修正バージョンがmitigationになり、影響を受けるイメージ/ホストはタグとして記録されます。コンテナの脆弱性は静的検出事項(イメージスキャン)として、ホストの脆弱性は動的検出事項(実行中ホストのスキャン)として記録されます。

詳細については、[Lacework APIドキュメント](https://docs.lacework.net/api/v2/docs)を参照してください。
