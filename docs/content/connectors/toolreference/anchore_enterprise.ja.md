---
title: "Anchore"
description: "DefectDojo で Anchore の Upstream Connector をセットアップする方法"
weight: 16
audience: pro
---
Anchore コネクタはユーザーの API トークンを使用して Anchore Enterprise からデータを取得します。製品は「Applications」に基づいてマッピング・検出されます。Applications は Anchore 内の複数の Image で構成されます。詳細は [Anchore Enterprise Documentation](https://docs.anchore.com/current/docs/sbom_management/application_groups/application_management_anchorectl/) を参照してください。

#### Connector Mappings

1. **Location** フィールドに Anchore の URL を入力します。これは Anchore にアクセスする際の URL です。
2. Secret フィールドに有効な API Key を入力します。これは Burp Service アカウントに紐づく API キーです。

Anchore のトークン作成に関する詳細は、公式の [Anchore documentation](https://docs.anchore.com/current/docs/) を参照してください。
