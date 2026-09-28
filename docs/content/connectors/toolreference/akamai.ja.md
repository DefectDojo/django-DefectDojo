---
title: "Akamai API Security"
description: "DefectDojo で Akamai API Security の Upstream Connector をセットアップする方法"
weight: 13
audience: pro
---
Akamai API Security コネクタは API キーを使用して Akamai API からセキュリティの検出事項を取得します。DefectDojo は Akamai 環境を検出し、アカウントに設定された**Application** と **Host** ごとに個別のレコードを作成します。

#### Prerequisites

Akamai API へのアクセス権を持つ API キーが必要です。自動操作とチームによる手動操作を明確に区別するため、DefectDojo 専用のサービスアカウントを作成することをお勧めします。

#### Connector Mappings

1. **Location** フィールドに Akamai API のベース URL を入力します。この URL は Akamai インスタンス固有のものです。例:
2. **Secret** フィールドに有効な **API Key** を入力します。

DefectDojo は **Application** と **Host** をそれぞれ別のレコードとしてマッピングします。各 Application はレコード一覧に `{name} (application)` として、各 Host は `{name} (host)` として表示されます。
