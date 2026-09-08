---
title: "Rapid7 InsightVM - Cloud Instance"
description: "DefectDojo で Rapid7 InsightVM - Cloud Instance の Upstream Connector をセットアップする方法"
weight: 113
audience: pro
---
Rapid7 InsightVM - Cloud Instanceコネクタは、**Rapid7 Insightプラットフォーム**（Cloud Integrations API v4）でホストされているInsightVMからアセットの脆弱性検出事項をインポートし、プラットフォームの脆弱性カタログで情報を付加します。DefectDojoは各InsightVM**サイト**についてRecordを作成します。

**ご注意ください:** このConnectorは、Rapid7 Insightクラウドプラットフォーム上で動作するInsightVM向けです。検出事項がお使いの**Security Console**（オンプレミス）から取得される場合は、代わりに[Rapid7 InsightVM](/connectors/toolreference/rapid7_insightvm/)コネクタをご利用ください。こちらはプラットフォームのAPIキーではなくコンソールの認証情報で認証します。

#### 前提条件

InsightVMを利用するInsightプラットフォームのアカウントと、プラットフォームの**APIキー**が必要です: [Rapid7 Insightプラットフォーム](https://insight.rapid7.com)で設定（歯車）メニュー > **API Keys** を開き、**User Key**（任意のロール）または**Organization Key**（プラットフォーム管理者）を生成します。表示された時点でキーをコピーしてください。キーは一度しか表示されません。

また、Insight URLに表示されるプラットフォームの**リージョン**（例: `us`、`us2`、`us3`、`eu`、`ca`、`au`、`ap`）も必要です。

#### Connector Mappings

1. **Location** フィールドにリージョンのAPIエンドポイントを入力します。例: `https://us.api.insight.rapid7.com`（`us` をお使いのリージョンに置き換えてください）。このフィールドには米国のエンドポイントがあらかじめ入力されています。
2. **API Key** フィールドにInsightプラットフォームのAPIキーを入力します。
3. 必要に応じて、インポートする検出事項を絞り込むために **Minimum Severity** を設定します。

各InsightVMサイトが1件のRecordになります。コネクタはプラットフォームの統合アセットを読み取り、その脆弱な検出事項を脆弱性カタログで情報を付加してインポートします。検出事項はオンプレミスのコネクタと同じ **Rapid7 InsightVM - Connectors Import** タイプでインポートされるため、両方のコネクタの結果はまとめて重複排除されます。
