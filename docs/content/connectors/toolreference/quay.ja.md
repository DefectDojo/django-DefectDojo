---
title: "Quay"
description: "DefectDojo で Quay の Upstream Connector をセットアップする方法"
weight: 110
audience: pro
---
QuayコネクタはProject Quay REST APIを使用して、コンテナリポジトリを検出し、Quay組み込みの**Clair**スキャナが生成した脆弱性レポートをインポートします。DefectDojoは各Quay**リポジトリ**についてRecordを作成し、Syncのたびにアクティブな各タグのイメージマニフェストのClairセキュリティレポートを読み取ります。

#### 前提条件

Quayインスタンスでセキュリティスキャン(Clair)が有効になっている必要があり、Quayの**OAuth 2アクセストークン**が必要です:

* Quayで、Organizationを作成(または開き)、**Applications** に移動し、OAuthアプリケーションを作成し、少なくとも**Read repositories**スコープで **Generate Token** を実行します。DefectDojo専用のアプリケーションを作成することをお勧めします。
* トークンはすべてのリクエストでBearerトークンとして送信され、ログに記録されることはありません。

#### Connector Mappings

1. **Location** フィールドにQuayのベースURLを入力します。例: `https://quay.io` またはセルフホストの `https://quay.example.com`。URLはHTTPSである必要があり、末尾にAPIパスを含めないでください — DefectDojoがAPIパスを自動的に構築します。
2. **Secret** フィールドにOAuthアクセストークンを入力します。
3. 必要に応じて **Namespace** を設定し、検出範囲を単一のQuay組織またはユーザーに限定します。空欄のままにすると、トークンが読み取れるすべてのリポジトリが検出されます。
4. 必要に応じて、インポートする検出事項を絞り込むために **Minimum Severity** を設定します。

DefectDojoは各Quay**リポジトリ**をRecordにマッピングします。各リポジトリについてアクティブなタグを列挙し、それらを一意のイメージマニフェストへと重複排除した上で(複数のタグで共有されるマニフェストは1回だけスキャンされます)、各マニフェストのClairレポートを読み取ります。Clairがまだスキャンを完了していないマニフェスト(例えばマルチアーキテクチャのマニフェストリストや、まだキュー中のイメージ)は、後のSyncまでスキップされます。各Clairの脆弱性は検出事項になります — 影響を受けるパッケージがコンポーネントとなり、修正バージョンが緩和策となり、Clairの**Negligible**/**Unknown**の深刻度は**Informational**として記録されます。

詳細については、[Project Quay APIドキュメント](https://docs.projectquay.io/api_quay.html)および[Clairドキュメント](https://quay.github.io/clair/)を参照してください。
