---
title: "Acunetix 360"
description: "DefectDojo で Acunetix 360 の Upstream Connector をセットアップする方法"
weight: 12
audience: pro
---
Acunetix 360 コネクタは、Acunetix 360 クラウドプラットフォーム(Invicti プラットフォーム)から**DAST 脆弱性の検出事項**をインポートします。DefectDojo はアカウント内でスキャンされた Web サイトを検出し、**Web サイト**ごとにレコードを作成します。Web サイトの検出事項は、その最新の完了済みスキャンから取得されます。

**ご注意ください:** このコネクタは(`online.acunetix360.com` のクラウド製品である)**Acunetix 360** 用です。異なる API を持つオンプレミス版の Acunetix Standard/Premium スキャナ用ではありません。

#### Prerequisites

Acunetix 360 のアカウントと**API 認証情報**が必要です。Acunetix 360 でアカウントメニュー \> **API Settings** を開き、**API User ID** を確認して **API Token** を生成してください。コネクタはこれらを HTTP Basic 認証情報として使用するため、手動によるチーム操作と自動操作を区別するために専用のサービスアカウントを利用することをお勧めします。

#### Connector Mappings

1. **Location** フィールドに Acunetix 360 の URL を入力します: `https://online.acunetix360.com`。
2. **API User ID** フィールドに API User ID を入力します。
3. **API Token** フィールドに API Token を入力します。
4. 必要に応じて、インポートする検出事項を制限するために **Minimum Severity** を設定します。

スキャンされた各 Web サイトが 1 件のレコードになります。検出事項はその Web サイトの最新の完了済みスキャンから取得されます。Acunetix 360 で **Accepted Risk** または **False Positive** としてマークされた脆弱性もインポートされますが、非アクティブ(risk-accepted または false-positive)としてフラグされるため、DefectDojo 側の製品にベンダーによるトリアージ結果が反映されます。
