---
title: "Bugcrowd"
description: "DefectDojo で Bugcrowd の Upstream Connector をセットアップする方法"
weight: 29
audience: pro
---
Bugcrowd コネクタは、Bugcrowd REST API を使用してバグバウンティおよび脆弱性開示プログラムからの提出をインポートします。DefectDojo は API トークンがアクセスできるプログラムを検出し、プログラムごとにレコードを作成して、そのプログラムの提出内容を検出事項としてインポートします。

#### Prerequisites

インポートしたいプログラムへのアクセス権を持つ Bugcrowd の **API トークン**が必要です。自動操作をチームによる手動操作と区別しやすくするため、DefectDojo 専用のサービスアカウントを作成することをお勧めします。トークンは Bugcrowd の **Organization settings \> API credentials** で生成します。提出、プログラム、ターゲットへの読み取りアクセスがあれば十分です。

#### Connector Mappings

1. **Location** フィールドに `https://api.bugcrowd.com` を入力します。
2. **Secret** フィールドに Bugcrowd API トークンを入力します。これは `Authorization: Token` ヘッダーとして送信されます。
3. 必要に応じて、インポートする検出事項を制限するために **Minimum Severity** を設定します。

各 Bugcrowd **プログラム**が 1 件のレコードになり、その提出内容は Bugcrowd の深刻度を維持したまま検出事項としてインポートされます。重複した提出は除外されるため、再インポートしても同じ問題に対して重複した検出事項が作成されることはありません。
