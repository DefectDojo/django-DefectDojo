---
title: インポート方法の比較
description: データを手動、API経由、またはコネクター経由でインポートする方法を学びます
weight: 1
aliases:
- /ja/en/connecting_your_tools/import_intro
---

DefectDojo が理解していることの一つは、企業ごとにセキュリティ要件がまったく異なるということです。万能なアプローチというものは存在しません。組織が変化するにつれて柔軟なアプローチを持つことが重要であり、DefectDojo ではその変化に合わせてセキュリティツールを柔軟な方法で連携させることができます。

## スキャンアップロード方法

DefectDojo がセキュリティツールから脆弱性レポートを受け取ると、そのレポートに含まれる脆弱性に基づいて検出事項が作成されます。DefectDojo は、これらの検出事項を一元管理するリポジトリとして機能し、あなたとあなたのチームがトリアージ、修復、またはその他の対応を行うことができます。

DefectDojo が検出事項レポートをアップロードする主な方法は2つあります。

* UI からの直接**インポート**
* **API** エンドポイント経由(自動化されたデータ取り込みが可能): [API Docs](/automation/api/api-v2-docs/) を参照してください

#### DefectDojo Pro の方法

<span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> ユーザーには、レポートとデータを処理するための追加の3つの方法があります。

* DefectDojo の API を活用するコマンドラインツールである **Universal Importer** または **DefectDojo CLI** 経由: [Universal Importer & DefectDojo-CLI guides](/import_data/pro/specialized_import/external_tools/) を参照してください
* 特定のツール向けの「すぐに使える」データ連携である **Connectors** 経由: [Connectors Guide](/connectors/upstream/about/) を参照してください
* インフラストラクチャスキャンを処理するために設計されたインポーターである、特定のツール向けの **Smart Upload** 経由: [Smart Upload Guide](/import_data/pro/specialized_import/smart_upload/) を参照してください

### アップロード方法の比較

|  | **UI Import** | **API** | **Connectors** <span style="background-color:rgba(242, 86, 29, 0.3)">(Pro)</span> | **Smart Upload**  <span style="background-color:rgba(242, 86, 29, 0.3)">(Pro)</span>|
| --- | --- | --- | --- | --- |
| **Supported Scan Types** | すべて: [Supported Tools](/supported_tools/) を参照 | すべて: [Supported Tools](/supported_tools/) を参照 | Akamai API Security, Anchore, AWS Security Hub, BurpSuite, Checkmarx ONE, Dependency-Track, IriusRisk, JFrog Xray, Probely, Semgrep, SonarQube, Snyk, Tenable, Wiz | Nexpose, NMap, OpenVas, Qualys, Tenable |
| **Automation?** | API 経由で利用可能: `/reimport` `/import` エンドポイント | [CLI Tools](/import_data/pro/specialized_import/external_tools/) または外部コードからトリガー | Connectors は本質的に自動化された機能です | API 経由で利用可能: `/smart_upload_import` エンドポイント |

### 製品階層と組織化

これらの各方法は、その場で製品階層を作成できます。製品階層とは、DefectDojo の製品タイプ、製品、エンゲージメント、またはテストを指し、データを関連するコンテキストに整理するのに役立つ DefectDojo 内のオブジェクトです。

* **脆弱性データは既存の製品階層にインポートできます。** 製品タイプ、製品、エンゲージメント、テストはすべて事前に作成しておくことができ、その後 DefectDojo 内のその場所にデータをインポートできます。
* **コンテキストに応じた製品階層はインポート時に作成することもできます。** レポートをインポートする際に、新しい製品タイプ、製品、エンゲージメント、および/またはテストを作成できます。これは DefectDojo の「auto-create context」オプションによって処理されます。DefectDojo OS では、このオプションは API からのみアクセスできます。DefectDojo OS での UI インポートでは、事前に製品階層を作成しておく必要があります。
