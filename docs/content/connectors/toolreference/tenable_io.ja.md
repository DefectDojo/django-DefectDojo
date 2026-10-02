---
title: "Tenable"
description: "DefectDojo で Tenable の Upstream Connector をセットアップする方法"
weight: 131
audience: pro
---
Tenable コネクタは **Tenable.io** REST API を使用してデータを取得します。 スキャンは Tenable VM の `/scans` エンドポイントから取得されます。

オンプレミス版の Tenable コネクタは現時点では利用できません。

#### **Connector Mappings**

1. Location フィールドに <https://cloud.tenable.com> を入力します。
2. Secret フィールドに有効な **API キー**を入力します。

詳細については、[Tenable の API ドキュメント](https://docs.tenable.com/vulnerability-management/Content/Settings/my-account/GenerateAPIKey.htm)を参照してください。
