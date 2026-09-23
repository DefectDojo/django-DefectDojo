---
title: "Rapid7 InsightVM"
description: "DefectDojo で Rapid7 InsightVM の Upstream Connector をセットアップする方法"
weight: 113
audience: pro
---
Rapid7 InsightVMコネクタは、お使いのInsightVM**Security Console**(API v3)からアセットの脆弱性検出事項をインポートし、コンソールのグローバル脆弱性カタログで情報を付加します。DefectDojoは各InsightVM**サイト**についてRecordを作成します。

#### 前提条件

DefectDojoからお使いのSecurity Consoleへのネットワークアクセスと、コンソールの**ユーザーアカウント**が必要です — そのログイン情報がHTTP Basic認証に使用されます。コンソールAPIはデフォルトでポート**3780**で提供されます。

#### Connector Mappings

1. **Location** フィールドに、ポートを含むSecurity ConsoleのURLを入力します — 例: `https://console.example.com:3780`。
2. **Username** フィールドにコンソールのユーザー名を入力します。
3. **Secret** フィールドにコンソールのパスワードを入力します。
4. 必要に応じて、インポートする検出事項を絞り込むために **Minimum Severity** を設定します。

各InsightVMサイトが1件のRecordになります。コネクタはサイトのアセットを走査し、脆弱性のある検出事項をインポートします。
