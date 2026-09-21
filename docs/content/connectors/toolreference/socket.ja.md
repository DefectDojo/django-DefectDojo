---
title: "Socket"
description: "DefectDojo で Socket の Upstream Connector をセットアップする方法"
weight: 126
audience: pro
---
Socket コネクタは [Socket.dev](https://socket.dev) API を使用して、**ソフトウェアサプライチェーンの検出事項**（依存関係に対する Socket のアラート — マルウェア、タイポスクワッティング、インストールスクリプト、既知の脆弱性、その他 70 以上のカテゴリ）をインポートします。DefectDojo はトークンがアクセスできる組織内のすべてのリポジトリを検出し、それぞれに対して Record を作成した上で、そのリポジトリの最新のフルスキャンからアラートをインポートします。

#### Prerequisites

Socket の **API トークン**（Socket ダッシュボードの **Settings → API Tokens** で作成する組織トークンで、`repo:list` とフルスキャンの読み取りスコープを持つもの）が必要です。トークンはベアラートークンとして送信され、ログに記録されることはありません。

#### Connector Mappings

1. **Location** フィールドには `https://api.socket.dev/v0` が自動入力されます。この値をそのまま使用するか、明示的に入力してください。
2. **Secret** フィールドに Socket API トークンを入力します。
3. 必要に応じて、**Minimum Severity** を設定してインポートする検出事項を絞り込みます。

DefectDojo は各**リポジトリ**を Record にマッピングし、その最新のフルスキャンからアラートをインポートします。各アラートは検出事項になります。深刻度は Socket 自身の評価(low、medium、high、critical)に基づき、影響を受けるパッケージはコンポーネントおよび PURL になり、アラートのカテゴリ(サプライチェーンリスク、品質、メンテナンス、脆弱性、ライセンス)はタグとして記録され、アラートの詳細は説明に反映されます。検出事項は静的検出事項として記録され、Socket のアラートキーで重複排除されます。

詳細については、[Socket API ドキュメント](https://docs.socket.dev/reference)を参照してください。
