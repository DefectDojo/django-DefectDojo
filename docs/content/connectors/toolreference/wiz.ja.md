---
title: "Wiz"
description: "DefectDojo で Wiz の Upstream Connector をセットアップする方法"
weight: 142
audience: pro
---
Wiz コネクタは **issue と脆弱性の検出事項**をインポートします。DefectDojo は **Wiz Project** ごとに Record を作成し、さらに Wiz テナント全体を対象とするテナントレベルの Record を作成します。この Record にはテナント自身の名前が付きます。例: **Wiz Tenant abc12**。

**このコネクタの利用に Wiz Project は必要ありません。** テナントに Project がない場合は、このテナントレベルの Record の Record をマッピングしてください。サービスアカウントが参照できるすべての issue と脆弱性の検出事項が DefectDojo にインポートされます。この Record は、どの Project にも含まれないリソースの検出事項も取得します。Project がすべてを網羅していない場合は、Project の Record と併せてマッピングしてください。Project の Record と このテナントレベルの Record の Record を両方マッピングすると、その Project の検出事項は 2 つの Asset にインポートされます。両方のビューが必要な場合にのみ行ってください。

Wiz コネクタを使用するには、サービスアカウントを作成する必要があります。詳細については [Wiz のドキュメント](https://docs.wiz.io/wiz-docs/docs/service-accounts-settings#add-a-service-account)を参照してください。ドキュメントにアクセスするには Wiz アカウントが必要です。

サービスアカウントは、以下の要件をすべて満たしている必要があります。いずれかを満たしていないサービスアカウントでも認証自体は成功しますが、何もインポートされません。

* **Type**: Custom Integration(GraphQL API)。
* **API scopes**: 最低限 `read:projects`、`read:issues`、`read:vulnerabilities` が必要です。Discover は常に Wiz へ Project 一覧を問い合わせるため、Project がないテナントでも `read:projects` は必要です。
* **Project visibility**: サービスアカウントは、インポートしたいすべての Wiz Project(またはすべての Project)に対してスコープが設定されている必要があります。issue を読み取れても Project の可視性がないアカウントは Project の Record を検出できず、このテナントレベルの Record の Record のみが利用可能になります。

#### **Connector Mappings**

1. Client ID フィールドに Wiz の Client ID を入力します。
2. Secret フィールドに Wiz の Client Secret を入力します。
