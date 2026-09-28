---
title: アップストリームコネクタ
description: DefectDojo とセキュリティツール群をシームレスに接続
summary: ''
date: 2023-09-07 16:06:50+02:00
lastmod: 2023-09-07 16:06:50+02:00
draft: false
weight: 0
chapter: true
sidebar:
  collapsed: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
pro-feature: true
aliases:
- /ja/import_data/pro/connectors/about_connectors/
- /ja/en/connecting_your_tools/connectors/about_connectors
---

<span style="background-color:rgba(242, 86, 29, 0.3)">注: アップストリームコネクタは DefectDojo Pro 限定の機能です。</span>

DefectDojo を使用すると、洗練された API 連携を構築でき、脆弱性データをどのように整理するかを完全にコントロールできます。

とはいえ、誰もが出発点を必要とします。そこで役立つのがアップストリームコネクタです。アップストリームコネクタ (旧称 **API Connectors**) は、セキュリティツールを接続し、できるだけ早く DefectDojo へのデータインポートを開始できるように設計されています。

現在、以下のツール向けにアップストリームコネクタをサポートしており、今後も追加予定です:

* **Acunetix 360**
* **Akamai API Security**
* **Anchore**
* **AWS Security Hub**
* **Azure DevOps**
* **Backstage**
* **Bitbucket**
* **Black Duck**
* **Bright Security**
* **Bugcrowd**
* **BurpSuite**
* **Censys**
* **Checkmarx ONE**
* **Cloudflare**
* **Cobalt.io**
* **Contrast**
* **Coverity**
* **CrowdStrike Falcon**
* **Deepfence ThreatMapper**
* **Dependency-Track**
* **Docker Scout**
* **Edgescan**
* **Endor Labs**
* **Escape**
* **Fairwinds Insights**
* **Fortify**
* **GitGuardian**
* **GitHub**
* **GitHub Advanced Security**
* **GitLab**
* **Google Cloud Security Command Center**
* **Group-IB ASM**
* **HackerOne**
* **Harbor**
* **Have I Been Pwned**
* **HCL AppScan**
* **Intigriti**
* **Intruder**
* **IriusRisk**
* **JFrog Xray**
* **Jira Service Management Assets**
* **Kubescape**
* **Lacework / FortiCNAPP**
* **Mend**
* **Microsoft Defender**
* **Microsoft Defender for Cloud**
* **MobSF**
* **NeuVector**
* **Nuclei (ProjectDiscovery Cloud)**
* **OpenVAS / Greenbone**
* **Probely**
* **Prowler**
* **Qualys**
* **Quay**
* **Rapid7 InsightAppSec**
* **Rapid7 InsightVM**
* **Rapid7 InsightVM - Cloud Instance**
* **runZero**
* **Semgrep**
* **ServiceNow CMDB**
* **Shodan**
* **Snyk**
* **Socket**
* **SonarQube**
* **Sonatype IQ**
* **Sysdig Secure**
* **Tenable**
* **Tenable Web App Scanning**
* **Veracode**
* **Wazuh**
* **Wiz**
* **YesWeHack**

各ツールのステップバイステップのセットアップ手順については、[ツール別コネクタセットアップ](../../toolreference/upstream/) のリファレンスを参照してください。

ほとんどのコネクタは **検出事項** をインポートします。一部は **Asset Connector** であり、検出事項をインポートする代わりに **アセットインベントリ** をインポートします — 検出事項をインポートするのではなく、製品 (アセット) と製品タイプ (組織) の階層を構築・維持します: **Azure DevOps**、**Backstage**、**Bitbucket**、**GitHub**、**GitLab**、**Jira Service Management Assets**、**ServiceNow CMDB**。(**runZero** は主に Asset Connector ですが、オプションで脆弱性を検出事項としてインポートすることもできます。)

これらの接続は、DefectDojo との API 速度の連携を提供し、ツールからの脆弱性データを自動的に取り込んで整理するために使用できます。

## コネクタページの見取り図

コネクタは 2 つのセクションに分けて表示され、それぞれの見出しの横に件数が示され、アルファベット順に並べられます:

* **Configured Connectors** — このインスタンスに存在するすべてのコネクタ設定です。1 つのツールに対して設定ごとに複数回表示されることがあり、それぞれのタイルは区別できるように `<Tool> - <label>` という形式のタイトルが付きます。同じツールの複数の設定がある場合は、ラベルの順に並びます。
* **Available Connectors** — まだ設定していない、サポート対象のツールすべてです。

見出しの横の件数は、現在表示されているコネクタの数であり、常に合計件数を示すわけではなく、検索ボックスや **Asset / Finding** タイプフィルターに応じて変化します。DefectDojo Pro Cloud では、**Request Upstream Connector** タイルはコネクタではないため、この件数には含まれません。

両方のセクションにそれぞれ専用の検索ボックスがあり、ツール名で一致するものを検索できます。

![各セクション見出しの横に件数が表示されたコネクタページ](images/upstream_counts.png)

[ダウンストリームコネクタ](/connectors/downstream/about/) と [認可コネクタ](/admin/sso/pro__authorization_connectors/) のページも同じレイアウトになっています。

## アップストリームコネクタ クイックスタート

DefectDojo の **Auto-Map** 設定を使用すれば、あっという間に最初のコネクタを稼働させることができます。

1. サポートされているツールから [コネクタ](../add_edit/) をセットアップします。
2. ツールのデータ階層を [Discover](../manage_operations/#discover-operations) します。
3. ツールで検出された脆弱性を DefectDojo に [Sync](../manage_operations/#sync-operations) します。

本当にそれだけです! また、コネクタを「簡単な」方法で作成した場合でも、後から作業内容を失うことなく、設定を簡単に変更できることを覚えておいてください。

## アップストリームコネクタの仕組み

接続しようとしているツールの API キーさえあれば、コネクタはわずか数分で追加できます。接続が機能するようになると、DefectDojo はツールの環境を **Discover** し、スキャンデータをどのように整理しているかを把握します。

例えば、5 つの異なるリポジトリの脆弱性をスキャンするように設定された BurpSuite ツールがあるとします。コネクタはこの組織構造を把握し、それらの個別のリポジトリを DefectDojo の 製品 / エンゲージメント / テスト の階層に変換するのに役立つ **Records** をセットアップします。**'Auto-Map Records'** を有効にしている場合、DefectDojo はその構造を自動的に学習してコピーします。

![image](images/_index.png)

**Record** のマッピングが設定されると、DefectDojo は定期的にスキャンデータのインポートを開始します。ツールによって検出された新しい脆弱性について常に最新の状態に保たれ、DefectDojo の **Findings** システムを使用して既存の脆弱性にすぐに取り組み始めることができます。

DefectDojo にさらにツールを追加する準備ができたら、インポートマッピングを別の設定に簡単に組み替えることができます。複数のツールを同じインポート先に脆弱性をインポートするように設定でき、作業内容を失うことなく、いつでもより適した形にセットアップを再編成できます。

## 自分のコネクタがサポートされていない

### UI からコネクタをリクエストする (DefectDojo Pro Cloud)

DefectDojo Pro Cloud では、UI から直接、まだサポートしていないツール向けのコネクタの構築を弊社チームに依頼できます:

1. **Connectors → Upstream Connectors** に移動します (DefectDojo に データを *取り込む* ツール向け)。issue トラッカーなどの送信系連携についても、**Connectors → Downstream Connectors** から同じ方法でリクエストできます。
2. **Available Connectors** セクションで **Request a Connector** をクリックします。
3. リクエストフォームに入力します。**Tool / Product Name**、**Tool API Base URL**、**Authentication Type**、およびその認証タイプに対応する認証情報はすべて必須です。弊社チームがコネクタを構築し、実際にツールに対して動作することを確認するために、到達可能なアドレスと有効な認証情報が必要となるためです。認証情報は安全に保存されます。任意で、ベンダーの Web サイト、ツールの API ドキュメントへのリンク、ユースケースを説明するメモを追加できます。
4. **Submit Request** をクリックします。リクエストが受け付けられたことを示す確認メッセージが表示されます。弊社チームは構築のサポートを評価するために各リクエストを確認します — リクエストを送信しても、コネクタが構築されることが保証されるわけではありません。

コネクタのリクエストには **グローバル Maintainer** 権限が必要で、**DefectDojo Pro Cloud でのみ** 利用可能です — このオプションは、セルフホスト (オンプレミス) のインスタンスには表示されません。

### 手動インポート

コネクタがない場合でも、DefectDojo は幅広いセキュリティツールの手動インポートに対応できます。[サポート対象ツール一覧](/supported_tools) と、データのインポートに関するガイドをご覧ください。

# **次のステップ**

* DefectDojo の **Pro UI** に切り替えて、**Import** ヘッダーの下にある **Connectors > Upstream Connectors** を開き、**Upstream Connectors** ページを確認してください。
* [最初のアップストリームコネクタを作成する](../add_edit/) ガイドに従ってください。
* 接続したセキュリティツールで [オペレーションの実行](../manage_operations/) のプロセスを確認し、データをインポートするようにどのように設定できるかを確認してください。
