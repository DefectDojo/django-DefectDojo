---
title: "Rapid7 InsightAppSec"
description: "DefectDojo で Rapid7 InsightAppSec の Upstream Connector をセットアップする方法"
weight: 112
audience: pro
---
Rapid7 InsightAppSecコネクタは、InsightAppSecクラウドプラットフォームから**DAST脆弱性検出事項**をインポートし、アタックモジュールのメタデータ(例: *SQL Injection*)、CVSSスコア、スキャンで収集された証拠を付加します。DefectDojoは各InsightAppSecの**アプリ**についてRecordを作成します。

**ご注意ください:** このConnectorは、以下の**Rapid7 InsightVM**コネクタとは別のものです — InsightAppSecはInsightプラットフォーム上のRapid7のクラウドDAST製品であり、InsightVMの検出事項はお使いのSecurity Consoleから取得されます。

#### 前提条件

InsightAppSecを利用するInsightプラットフォームのアカウントと、プラットフォームの**APIキー**が必要です: [Rapid7 Insightプラットフォーム](https://insight.rapid7.com)で設定(歯車)メニュー > **API Keys** を開き、**User Key**(任意のロール)または**Organization Key**(プラットフォーム管理者)を生成します。表示された時点でキーをコピーしてください — 一度しか表示されません。

また、Insight URLに表示されるプラットフォームの**リージョン**(例: `us`、`us2`、`us3`、`eu`、`ca`、`au`、`ap`)も必要です。

#### Connector Mappings

1. **Location** フィールドにリージョンのAPIエンドポイントを入力します — 例: `https://us.api.insight.rapid7.com`(`us` をお使いのリージョンに置き換えてください)。
2. **API Key** フィールドにInsightプラットフォームのAPIキーを入力します。
3. 必要に応じて、インポートする検出事項を絞り込むために **Minimum Severity** を設定します。

各InsightAppSecアプリが1件のRecordになります。**オープン**な脆弱性(UnreviewedまたはVerified)のみがインポートされます — Rapid7がRemediated、False Positive、Ignored、またはDuplicateとマークした検出事項は除外されるため、再インポートによってDefectDojo内でそれらがクローズされます。深刻度は直接マッピングされます(`SAFE` と `INFORMATIONAL` はInfoとしてインポートされます)。
