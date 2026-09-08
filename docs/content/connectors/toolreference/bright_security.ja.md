---
title: "Bright Security"
description: "DefectDojo で Bright Security の Upstream Connector をセットアップする方法"
weight: 28
audience: pro
---
Bright Security コネクタは [Bright](https://brightsec.com)(旧 NeuraLegion)の API を使用して**DAST の検出事項**をインポートします。DefectDojo はトークンがアクセスできるすべてのスキャンを検出し、完了済みスキャンごとにレコードを作成して、そのスキャンの issue を検出事項としてインポートします。

#### Prerequisites

Bright アプリの **User settings → API keys** で作成した Bright の**API キー**(`Org` または個人キー)が必要です。このキーは `Authorization: Api-Key` ヘッダーで送信され、ログに記録されることはありません。

#### Connector Mappings

1. **Location** フィールドには `https://app.brightsec.com` が自動入力されます。この値をそのまま使用するか、Bright のホストを明示的に入力してください。
2. **Secret** フィールドに Bright の API キーを入力します。
3. 必要に応じて、インポートする検出事項を制限するために **Minimum Severity** を設定します。

DefectDojo は完了済みの各**スキャン**を 1 件のレコードにマッピングし、各**issue**を検出事項にマッピングします。深刻度は Bright 自身の評価(Critical/High/Medium/Low)から取得され、CVSS スコア、CWE、修復情報が引き継がれ、影響を受けるエントリーポイントがエンドポイントとなり、リクエスト/レスポンスの証跡が説明に含まれます。検出事項は動的な検出事項として記録され、Bright の issue id で重複排除されます。

詳細は [Bright API documentation](https://docs.brightsec.com/) を参照してください。
