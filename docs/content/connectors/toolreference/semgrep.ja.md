---
title: "Semgrep"
description: "DefectDojo で Semgrep の Upstream Connector をセットアップする方法"
weight: 118
audience: pro
---
このコネクタは、Semgrep REST APIを使用してデータを取得します。

#### Connector Mappings

**Location** フィールドに `https://semgrep.dev/api/v1/` を入力します。

1. **Secret** フィールドに有効なAPIキーを入力します。これはTokensページで確認できます:
​
左側のナビゲーションバーの「Settings」 \> Tokens \> Create new token ([https://semgrep.dev/orgs/\-/settings/tokens](https://semgrep.dev/orgs/-/settings/tokens))

詳細については[Semgrepのドキュメント](https://semgrep.dev/docs/semgrep-cloud-platform/semgrep-api/#tag__badge-list)を参照してください。
