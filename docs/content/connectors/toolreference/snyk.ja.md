---
title: "Snyk"
description: "DefectDojo で Snyk の Upstream Connector をセットアップする方法"
weight: 125
audience: pro
---
Snykコネクタは、Snyk REST APIを使用してデータを取得します。

#### Connector Mappings

1. **Location** フィールドに **[https://api.snyk.io/rest](https://api.snyk.io/v1)** または(リージョナルなEUデプロイメントの場合)**[https://api.eu.snyk.io/rest](https://api.eu.snyk.io/v1)** を入力します。
2. **Secret** フィールドに有効なAPIキーを入力します。APIトークンは、Snykのユーザーの**[アカウント設定](https://docs.snyk.io/getting-started/how-to-obtain-and-authenticate-with-your-snyk-api-token)**[ページ](https://docs.snyk.io/getting-started/how-to-obtain-and-authenticate-with-your-snyk-api-token)にあります。

詳細については[Snyk APIドキュメント](https://docs.snyk.io/snyk-api)を参照してください。
