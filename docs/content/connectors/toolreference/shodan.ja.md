---
title: "Shodan"
description: "DefectDojo で Shodan の Upstream Connector をセットアップする方法"
weight: 123
audience: pro
---
Shodanコネクタは、Shodan REST APIを使用して、インターネットに露出しているホストでShodanが観測した脆弱性 (CVE) をインポートします。お使いの資産に取り込み範囲を限定するShodan検索クエリを指定し、DefectDojoは一致する各ホストについてRecordを作成し、そのCVEを検出事項としてインポートします。

#### 前提条件

Shodanの**Account**ページで確認できるShodan APIキーが必要です。脆弱性データ付きのホスト検索には、Shodanのメンバーシップまたは有料APIプランが必要です — 無料プランでは検索結果をページングできません。

#### Connector Mappings

1. **Location** フィールドに `https://api.shodan.io` を入力します。
2. **API Key** フィールドにShodan APIキーを入力します。
3. **Search Query** フィールドに、お使いの組織の資産に取り込み範囲を限定するShodanクエリを入力します — 例: `hostname:example.com`、`net:203.0.113.0/24`、`org:"Example Inc"`。このクエリに一致するホストのみがインポートされるため、自組織が所有するインフラストラクチャに範囲を限定してください。
4. 必要に応じて、インポートする検出事項を絞り込むために **Minimum Severity** を設定します。

一致する各ホストが1件のRecordになり、そのホストの露出しているサービス上でShodanが検出した各CVEが検出事項としてインポートされます — 深刻度はCVSSスコアから導出され、利用可能な場合はEPSSとCISA KEVのコンテキストが含まれます。検索結果の各ページはShodanのクエリクレジットを1つ消費します。
