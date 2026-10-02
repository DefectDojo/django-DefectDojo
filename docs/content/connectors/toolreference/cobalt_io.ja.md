---
title: "Cobalt.io"
description: "DefectDojo で Cobalt.io の Upstream Connector をセットアップする方法"
weight: 37
audience: pro
---
Cobalt.ioコネクタは、Cobalt.io API（v2）を使用して、Cobalt.io組織からペネトレーションテストの検出事項を取得します。DefectDojoは、APIトークンでアクセスできるすべての組織を検出し、Cobaltがペネトレーションテストを行う単位である**アセット**ごとに個別のレコードを作成します。

#### Prerequisites

Cobalt.ioの**個人用APIトークン**が必要です。自動化された操作とチームによる手動操作を明確に区別できるよう、DefectDojo専用のサービスアカウントを作成することをお勧めします。Cobalt.io UIの**Settings > API Tokens**からトークンを生成してください。組織トークンは自動的に検出されるため、指定する必要はありません。

#### Connector Mappings

1. **Location**フィールドにCobalt.io APIのベースURLを入力します: `https://api.cobalt.io`（またはリージョンごとのホスト、例: `https://api.us.cobalt.io`）。
2. **Secret**フィールドに**個人用APIトークン**を入力します。
3. 必要に応じて、同期を単一の組織に固定するために**Organization Token**を入力します。空欄のままにした場合、DefectDojoは個人用APIトークンがアクセスできるすべての組織を同期します。

DefectDojoは、Cobalt.ioの各**アセット**を個別のレコードとしてマッピングします。マッピングされた各アセットについて検出事項がインポートされ、Cobalt.io側のステータス（例: `valid_fix`、`wont_fix`、`invalid`）によってDefectDojo内の検出事項のステータスが決まります。
