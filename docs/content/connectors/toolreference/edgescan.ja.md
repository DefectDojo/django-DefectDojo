---
title: "Edgescan"
description: "DefectDojo で Edgescan の Upstream Connector をセットアップする方法"
weight: 52
audience: pro
---
Edgescanコネクタは、Edgescan REST APIを使用して、Edgescanアカウント全体のオープンな脆弱性をインポートします。DefectDojoは、すべてのEdgescanの**アセット**を列挙してそれぞれについてレコードを作成し、そのアセットのオープンな脆弱性を検出事項としてインポートします。アセットごとの個別設定はありません。

#### Prerequisites

EdgescanのAPIトークンが必要です。Edgescanアカウントの**Account settings > API tokens**からラベルを入力し、**Create**をクリックして、生成されたトークンをコピーします（トークンは一度しか表示されません）。自動化された操作を区別しやすくするため、コネクタ専用のアカウントを使用することをお勧めします。

#### Connector Mappings

1. **Location**フィールドにEdgescanのURLを入力します。標準的なホスト版プラットフォームの場合は`https://live.edgescan.com`、異なる場合はテナントのホストを入力してください。
2. **Secret**フィールドにEdgescanのAPIトークンを入力します。これは`X-API-TOKEN`ヘッダーとして送信されます。
3. 必要に応じて、インポートする検出事項を制限するために**Minimum Severity**を設定します。

各Edgescanアセットはレコードとなり、そのアセット上のオープンな脆弱性はそれぞれ検出事項としてインポートされます。深刻度は、Edgescanの数値スケール（1〜5）からDefectDojoの情報〜重大にマッピングされます。また、Edgescanが提供している場合は、CVE参照、CWE、CVSS v3ベクトルも含まれます。
