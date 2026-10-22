---
title: 📊 Proの機能一覧
description: DefectDojoのPro機能一覧
draft: 'false'
weight: 4
chapter: true
exclude_search: true
audience: pro
aliases:
- /ja/en/about_defectdojo/pro_features
---

DefectDojo Proが提供する多くの追加機能の一覧と、実際の動作を確認できるドキュメントへのリンクをご紹介します。

## UXの改善

### Pro UI

DefectDojoのUIは、DefectDojo Proにおいてより高速で、より機能的に、そして完全にカスタマイズ可能に作り直されており、エンタープライズレベルのデータ量をより快適に扱えるようになっています。ダークモードも搭載しています。  
詳細は[Pro UIガイド](/get_started/about/ui_pro_vs_os/)をご覧ください。

![image](images/enabling_deduplication_within_an_engagement_2.png)

### グローバル検索

検出事項、アセット、エンゲージメントなどを、トップバーの検索ボックスひとつから見つけることができます。DefectDojo Proのグローバル検索は、高速でタイプミスにも強いPostgresの全文検索を使って、あらゆるオブジェクトを横断的に検索します。

詳細は[グローバル検索ガイド](/navigation/pro__global_search/)をご覧ください。

### アセット/組織

DefectDojo Proでは、大量のリポジトリやその他のビジネス構造を、より分かりやすく組織的に可視化できます。詳細については[アセット/組織のドキュメント](/asset_modelling/pro_hierarchy/asset_hierarchy/)をご覧ください。

![image](images/asset_hierarchy_diagram.png)

### 検出事項の優先度

DefectDojo Proは、優先度とリスクに基づいて検出事項を事前にトリアージできるため、チームは最も重大な問題を最初に特定して修正できます。
詳細は[検出事項の優先度ガイド](/asset_modelling/pro_hierarchy/priority_sla/)をご覧ください。

### ルールエンジン

DefectDojo Proのルールエンジンを使用すると、プログラミング経験がなくても、自動化された一括操作をスクリプト化したり、検出事項やその他のオブジェクトを処理するカスタムワークフローを構築したりできます。

詳細は[ルールエンジンガイド](/automation/rules_engine/about)をご覧ください。

![image](images/rules_engine_4.png)

### Sensei

DefectDojo Proの**Sensei**(BETA)は、AIを活用したスキャン&修正機能です。GitHub App経由でリポジトリを接続すると、Senseiがそれをスキャンして検出事項をインポートし、修正のためのプルリクエストを作成します。プレビュー優先のワークフローになっているため、承認するまでは何も実行されず、LLMのコストも発生しません。

詳細は[Senseiガイド](/sensei/about_sensei/)をご覧ください。

### Proのダッシュボードとレポート

[インスタントレポートとメトリクス](/get_started/about/ui_pro_vs_os/#new-dashboards)を生成して、アプリやリポジトリのセキュリティ状況を共有したり、セキュリティツールを評価したり、セキュリティ問題への対応におけるチームのパフォーマンスを分析したりできます。

ランディングページのグラフィックはSVGファイルとしてエクスポートでき、グラフィック作成に使用されたデータも表としてエクスポートできます。 

さらに、DefectDojo Proにはいくつかの新しい[インサイトダッシュボード](/metrics_reports/pro_metrics/pro__overview/)が含まれており、セキュリティプログラムのさまざまな関係者向けに強化されたメトリクスを提供します。

### 重複排除のチューニング

高度な重複排除設定により、DefectDojoが重複した検出事項をどのように識別・管理するかを細かく調整できます。同一ツール内、**ツール間**、および再インポート時の重複排除を調整することで、選択したすべてのセキュリティツールと脆弱性の検出事項との間で精密なマッチングを実現できます。 

詳細は[重複排除チューニングガイド](/triage_findings/finding_deduplication/pro__deduplication_tuning/)をご覧ください。

![image](images/deduplication_tuning.png)

## インポートの効率化

### 追加のインポートオプション

DefectDojo Proには、[Universal Importer](/import_data/pro/specialized_import/external_tools/)、[アップストリームコネクタ](/connectors/upstream/about/)、[Universal Parser](/supported_tools/parsers/universal_parser/)、[Smart Upload](/import_data/pro/specialized_import/smart_upload/)という4つの追加インポート方法が含まれています。

![image](images/pro_import_methods.png)


### バックグラウンドインポート

エンタープライズレベルのレポートに対して、DefectDojo Proは検出事項をバックグラウンドで処理する最適化されたアップロード方法を提供します。

### CLIツール

Universal ImporterとDefectDojo-CLIアプリを使用すれば、APIのスクリプト作成を必要とせずに、DefectDojo Proインスタンスへのデータのインポート、再インポート、エクスポートを行うコマンドラインパイプラインを素早く構築できます(Windows、Macintosh、Linuxで利用可能)。

詳細は[外部ツールガイド](/import_data/pro/specialized_import/external_tools/)をご覧ください。

### アップストリームコネクタ

DefectDojoは、エンタープライズレベルのスキャンツールに即座に接続して新しい検出事項データをインポートできます。これにより、API呼び出しやcronジョブを設定する必要のない、そのまま使える自動インポートパイプラインが作成されます。 

詳細は[アップストリームコネクタガイド](/connectors/upstream/about/)をご覧ください。

![image](images/add_edit_connectors_2.png)

アップストリームコネクタでサポートされているツールには、以下が含まれます。

* Anchore
* AWS Security Hub
* BurpSuite
* Checkmarx ONE
* Dependency-Track
* Probely
* Semgrep
* SonarQube
* Snyk
* Tenable
* Wiz

### Universal Parser(ベータ版)

サポート対象外のツールやカスタマイズされたスキャンツールを使用している場合、あるいはDefectDojoにレポートを少し違った形で処理してほしい場合は、DefectDojo ProのUniversal Parserを使用して、任意の.jsonまたは.csvレポートを、対応可能な検出事項のセットに変換できます。パーサーは、お好みの方法でデータを解析・マッピングします。

詳細は[Universal Parserガイド](/import_data/pro/specialized_import/universal_parser//)をご覧ください。

![image](images/universal_parser_3.png)

## オプション機能の管理

上記の機能の多くはオプションであり、フィーチャーフラグの背後で提供されるため、準備が整った時点で導入できます。スーパーユーザーは、サポートに連絡することなく、**設定 > フィーチャーフラグ**からほとんどの機能を直接オン/オフできます。

機能を有効にする方法や、インストールタイプによって機能がロックされていたり利用できなかったりする理由については、[フィーチャーフラグ](/admin/feature_flags/pro__feature_flags/)ガイドをご覧ください。

## サポート

DefectDojo Proのサブスクリプションには、オンプレミスおよびクラウドの両方のインストールに対する世界クラスのサポートが含まれています。私たちのチームは、貴組織がDefectDojo Proを導入し、その活用を最大化できるようサポートいたします。サブスクリプションには以下が含まれます。

- **包括的なサポート**:チーム全体をサポートするため、サポートチケットとシートを無制限にご利用いただけます。
- **専任のエンジニアリング対応**:ユーザーから報告された問題、バグ、機能リクエストは、エンジニアリングチームによって優先的に対応されます。
- **SaaS管理**:すべてのSaaSインスタンスに対して、監視、メンテナンス、バックアップを提供します。
