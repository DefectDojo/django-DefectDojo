---
title: "HackerOne"
description: "DefectDojo で HackerOne の Upstream Connector をセットアップする方法"
weight: 69
audience: pro
---
HackerOneコネクタは、HackerOne REST APIを使用して、バグバウンティまたは脆弱性開示プログラムからレポートをインポートします。DefectDojoはトークンがアクセスできる各プログラムのRecordを作成し、そのレポートを検出事項としてインポートします。

#### Prerequisites

このコネクタはHackerOneの**customer** APIを使用しており、**organization APIトークン**が必要です。ユーザー設定の個人トークンはhacker APIに対してのみ有効で、ここでは認証できません。

1. HackerOneで**Organization Settings > API Tokens**に移動します。
2. トークンを作成し、**identifier**と**token**の両方の値を控えておきます。プログラムへの読み取りアクセスがあれば十分です。

#### Connector Mappings

1. **Location**フィールドに`https://api.hackerone.com`を入力します。
2. **API Token Identifier**フィールドにトークンの**identifier**を入力します。
3. **API Token**フィールドにトークンの値を入力します。
4. 必要に応じて**Minimum Severity**を設定し、インポートする検出事項を制限できます。

各プログラムがRecordとなり、そのレポートはHackerOneの深刻度評価を維持したまま検出事項としてインポートされます。
