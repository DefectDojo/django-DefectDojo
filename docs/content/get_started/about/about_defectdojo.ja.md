---
title: DefectDojoについて
date: 2021-02-02 20:46:29+01:00
draft: false
type: docs
weight: 1
aliases:
- /ja/en/about_defectdojo/about_docs
---

<div class="version-opensource">

![image](images/dashboard.png)

</div>
<div class="version-pro">

![image](images/Introduction_to_Dashboard_Features.png)

</div>


<span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo, Inc.およびオープンソースコントリビューターは、DefectDojoのCommunity版とPro版の両方をサポートするために本ドキュメントを管理しています。</span>

## DefectDojoとは?

DefectDojoは、Developer Security Operations(DevSecOps)プラットフォームです。DefectDojoは、お使いのセキュリティツール群を自動的に集約することでDevSecOpsを効率化し、セキュリティ業務を簡単に整理して、組織のセキュリティ体制を他のステークホルダーに報告できるようにします。

セキュリティプロセスの自動化と統合された開発パイプラインはDefectDojoの最終目標ですが、このソフトウェアの中核は、多数のセキュリティツールからのレポートを取り込み、整理し、標準化するためのセキュリティ脆弱性向けバグトラッカーです。

### DefectDojoは何をするのか?

DefectDojoには、セキュリティツールの結果を強化・調整するためのスマートな機能が備わっており、以下のようなことが可能です。

- コンテキストに応じてセキュリティの検出事項を追跡・報告する
- コンテキストに応じてSLAを適用する
- 誤検知、リスク受容、その他のトリアージ判断を処理する
- DefectDojoの重複排除アルゴリズムを使用して重複を排除する
- 外部のプロジェクト追跡ソフトウェアと連携する。
- CI/CD連携を使用して、リポジトリや開発ブランチ全体にわたるメトリクス/レポートを提供する。
- 従来型のペネトレーションテスト管理を調整する。
- 脆弱性修正手順のSLAを設定・適用する。
- セキュリティ脆弱性に対するリスク受容を作成・追跡する。

最終的に、DefectDojoの製品:エンゲージメントモデルにより、開発環境の棚卸しを行い、新しいセキュリティの検出事項を即座にコンテキストの中に位置付けることができます。

---
以下は、DefectDojoの共同創業者兼CTOであるMatt Tesauroによる、DefectDojoの導入方法の例です。
<iframe width="560" height="315" src="https://www.youtube.com/embed/44vv-KspHBs?si=OwfGHs2VTQ886-FB" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

---

## DefectDojo Open-Source

DefectDojoのコア機能は、DefectDojo Open-Sourceで利用できます。

このエディションのDefectDojoには、以下が含まれます。

- 500以上のサポート対象ツールすべてに対応したインポート/再インポート
- REST API
- 重複排除機能
- 限定的なUI、メトリクス、レポート機能
- Jira連携機能

検出事項の量が少ないチームにとって、DefectDojo Open-Sourceは最適な出発点です。

### インストールガイド

DefectDojoのOpen-Source版をインストールするには、いくつかのサポートされた方法があります([GitHubで公開](https://github.com/DefectDojo/django-DefectDojo))。

[Docker Compose](https://github.com/DefectDojo/django-DefectDojo/blob/master/readme-docs/DOCKER.md)は、DefectDojoの実行に必要なコアプログラムとサービスをインストールする最も簡単な方法です。
[アーキテクチャ](/get_started/open_source/architecture/)ガイドでは、DefectDojoが使用する各サービスとコンポーネントの概要を説明しています。
[本番環境での実行](/get_started/open_source/running-in-production/)では、Docker Composeを使用して本番サーバーでDefectDojoを実行するためのシステム要件、パフォーマンス調整、メンテナンスプロセスを一覧にしています。

Kubernetesは、Open-Sourceレベルでは完全にはサポートされていませんが、このガイドを参照し、DefectDojoをKubernetesアーキテクチャに統合するための出発点として利用できます。

Open-Sourceのインストールで問題が発生した場合は、[OWASP Slack](https://owasp.org/slack/invite)で質問することを強くお勧めします。コミュニティメンバーが#defectdojoチャンネルで活動しており、直面している問題の解決を手伝ってくれます。

## 🟧 DefectDojo Pro エディション

<iframe width="560" height="315" src="https://www.youtube.com/embed/XUES0mCCGOI?si=2GEnd1iHlLcQE0R3" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

DefectDojo, Inc.は、商用目的でこのソフトウェアのPro版をホスティングしています。洗練されたモダンなUIに加えて、DefectDojo Proには以下が含まれます。

* [コネクタ](/connectors/upstream/about/): Checkmarx One、BurpSuite、Semgrepなど、エンタープライズレベルのスキャナとすぐに使えるAPI連携
* **設定可能なインポート方法**: [ユニバーサルパーサー](/supported_tools/parsers/universal_parser/)、[スマートアップロード](/import_data/pro/specialized_import/smart_upload/)
* お使いのシステムとの迅速な連携のための**[CLIツール](/import_data/pro/specialized_import/external_tools/)**
* **[追加のプロジェクト追跡連携](/connectors/issue_tracking/)**: ServiceNow、Azure DevOps、GitHub、GitLab
* 経営層向けレポートと高レベルな分析のための**[改善されたメトリクス](/metrics_reports/pro_metrics/pro__overview/)**
* システム全体で最も緊急度の高い検出事項を特定するための**[優先度とリスク](/asset_modelling/pro_hierarchy/priority_sla/)**
* 組織向けの**プレミアムサポート**および導入ガイダンス

Pro版は、クラウドホスト型のSaaSとして提供されているほか、オンプレミスへのインストールにも対応しています。

DefectDojo Proの詳細については、[料金ページ](https://defectdojo.com/pricing)をご覧ください。

## オンラインデモ

DefectDojoのOpen-Source版とPro版の両方について、オンラインデモをご利用いただけます。どちらも以下の認証情報でアクセスできます。

- ユーザー名: `admin`
- パスワード: `1Defectdojo@demo#appsec`

これらのデモにはサンプルデータが読み込まれており、毎日リセットされます。

### Open-Sourceデモ

DefectDojo(Open-Source版)の稼働例は[https://demo.defectdojo.org/](https://demo.defectdojo.org/)でご覧いただけます。

### Proデモ

DefectDojo Proの稼働例は
[https://pro.demo.defectdojo.com/](https://pro.demo.defectdojo.com/)でご覧いただけます。

## DefectDojoを学ぶ

Pro版・Open-Source版のどちらのユーザーであっても、DefectDojoを使い始める際に役立つ多くのリソースをご用意しています。

* サポート対象の[セキュリティツール連携](/supported_tools/)を確認し、DefectDojoをお使いのDevSecOpsプログラムに組み込む際の参考にしてください。
* 私たちのチームは、チュートリアルやOffice Hoursイベントのアーカイブなどのコンテンツを掲載した[YouTubeチャンネル](https://www.youtube.com/@defectdojo)を運営しています。

## お問い合わせ

DefectDojo, Inc.チームへのお問い合わせは、いつでも[hello@defectdojo.com](mailto:hello@defectdojo.com)までご連絡ください。

私たちは[LinkedIn](https://www.linkedin.com/company/33245534)で定期的に情報を発信しているほか、AppSec専門家向けのオンラインプレゼンテーションをライブまたはオンデマンドで提供しています。今後開催予定のイベントについては[イベントページ](https://defectdojo.com/events)をご覧いただくか、過去のプレゼンテーションを[YouTubeチャンネル](https://www.youtube.com/@defectdojo)でご視聴ください。

### ステッカー

かっこいいDefectDojoのノートPC用ステッカーをお探しですか? DefectDojoコミュニティの一員であることへの感謝の印として、無料のDefectDojoステッカーをお申し込みいただけます。詳細については[こちらのリンク](https://defectdojo.com/defectdojo-sticker-request)をご覧ください。
