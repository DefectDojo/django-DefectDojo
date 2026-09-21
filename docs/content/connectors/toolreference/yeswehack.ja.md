---
title: "YesWeHack"
description: "DefectDojo で YesWeHack の Upstream Connector をセットアップする方法"
weight: 143
audience: pro
---
YesWeHack コネクタは、YesWeHack REST API を使用して、バグバウンティおよび脆弱性開示プログラムからレポートをインポートします。DefectDojo は、トークンがアクセスできるプログラムごとに Record を作成し、そのレポートを検出事項としてインポートします。

#### Prerequisites

YesWeHack の **Personal Access Token(PAT)**が必要です。プログラムへの読み取りアクセス権があれば十分です。一部のアカウントではトークン作成時に TOTP/MFA が必要ですが、作成後はトークンの値自体をコネクタが使用します。

1. YesWeHack でアカウント設定を開き、**API / Personal Access Tokens** に移動します。
2. トークンを作成し、その値をコピーします。値は一度しか表示されません。

#### Connector Mappings

1. **Location** フィールドに `https://api.yeswehack.com/` を入力します。
2. **Secret** フィールドに Personal Access Token を入力します。
3. 必要に応じて、**Minimum Severity** を設定してインポートする検出事項を絞り込みます。選択した深刻度を下回る検出事項はインポートされません。

DefectDojo は、トークンがアクセスできるプログラムごとに個別の Record を作成し、各レポートを検出事項としてインポートします。検出事項の深刻度はレポートの CVSS 評価から取得され(利用できない場合はトリアージの優先度にフォールバックします)、そのステータスはレポートのワークフロー状態を反映します — 例えば、解決済みのレポートは緩和済みとしてインポートされ、無効または対象外とマークされたレポートは非アクティブとしてインポートされます。
