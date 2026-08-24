---
title: "Wiz"
description: "DefectDojo で Wiz の Upstream Connector をセットアップする方法"
weight: 142
audience: pro
---
Wiz コネクタを使用するには、サービスアカウントを作成する必要があります。詳細については [Wiz のドキュメント](https://docs.wiz.io/wiz-docs/docs/service-accounts-settings#add-a-service-account)を参照してください。ドキュメントにアクセスするには Wiz アカウントが必要です。

サービスアカウントは、以下の要件をすべて満たしている必要があります。いずれかを満たしていないサービスアカウントでも認証自体は成功しますが、何もインポートされません。

* **Type**: Custom Integration(GraphQL API)。
* **API scopes**: 最低限 `read:projects`、`read:issues`、`read:vulnerabilities` が必要です。
* **Project visibility**: サービスアカウントは、インポートしたいすべての Wiz Project(またはすべての Project)に対してスコープが設定されている必要があります。コネクタはまず Wiz Project を検出し、その後各 Project の検出事項を取得します — issue を読み取れても Project の可視性がないアカウントは Project を 1 つも検出できないため、インポートするものがなく、双方からエラーも報告されません。

#### **Connector Mappings**

1. Client ID フィールドに Wiz の Client ID を入力します。
2. Secret フィールドに Wiz の Client Secret を入力します。
