---
title: "BurpSuite"
description: "DefectDojo で BurpSuite の Upstream Connector をセットアップする方法"
weight: 30
audience: pro
---
DefectDojo の Burp コネクタは、データを取得するために Burp の GraphQL API を呼び出します。

#### Prerequisites

このコネクタをセットアップする前に、Burp Service Account の API キーが必要です。Burp のユーザーアカウントにはデフォルトで API キーがないため、この目的のために新しいユーザーを作成する必要がある場合があります。

API キーを持つ Service Account ユーザーのセットアップ方法については、[Burp Documentation](https://portswigger.net/burp/documentation/enterprise/user-guide/api-documentation/create-api-user) を参照してください。

#### Connector Mappings

1. **Location** フィールドに Burp のルート URL を入力します。これは Burp ツールにアクセスする際の URL です。
2. Secret フィールドに有効な API Key を入力します。これは Burp Service アカウントに紐づく API キーです。

Burp API の詳細については、公式の [Burp documentation](https://portswigger.net/burp/extensibility/enterprise/graphql-api/index.html) を参照してください。
