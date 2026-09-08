---
title: "Escape"
description: "DefectDojo で Escape の Upstream Connector をセットアップする方法"
weight: 55
audience: pro
---
Escapeコネクタは、[Escape](https://escape.tech) APIを使用して**APIセキュリティ（DAST）の検出事項**をインポートします。DefectDojoは、トークンがアクセスできるすべての組織と、それぞれの組織内のすべてのアプリケーションを列挙し、スキャンがあるアプリケーションごとにレコードを作成して、そのアプリケーションの最新スキャンのissueを検出事項としてインポートします。アプリケーションごとの個別設定はありません。

#### Prerequisites

Escapeの**APIキー**が必要です。これはEscapeアプリの**Settings → API keys**で作成します。このキーは`Authorization: Key`ヘッダーで送信され、ログに記録されることはありません。

#### Connector Mappings

1. **Location**フィールドには`https://public.escape.tech/v2`が自動入力されます。この値をそのまま使用するか、EscapeのAPIホストを明示的に入力してください。
2. **Secret**フィールドにEscapeのAPIキーを入力します。
3. 必要に応じて、インポートする検出事項を制限するために**Minimum Severity**を設定します。

DefectDojoは、各**アプリケーション**をレコードにマッピングし、スキャンの各**issue**を検出事項にマッピングします。深刻度はEscapeの評価（重大/高/中/低）に基づき、CWEが引き継がれ、OWASPカテゴリとHTTPメソッドがタグになり、影響を受けるURLがエンドポイントになり、修復ガイダンスも含まれます。検出事項は動的検出事項として記録され、Escapeのissue IDで重複排除されます。

詳細については、[Escape APIのドキュメント](https://docs.escape.tech/)を参照してください。
