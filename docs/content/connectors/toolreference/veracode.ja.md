---
title: "Veracode"
description: "DefectDojo で Veracode の Upstream Connector をセットアップする方法"
weight: 137
audience: pro
---
Veracode コネクタは、Veracode プラットフォームからアプリケーションの検出事項をインポートし、スキャンタイプごとに **SAST**、**DAST**、**SCA**、**Manual** の検出事項タイプに分けます。DefectDojo は Veracode の**アプリケーション**ごとに Record を作成します。

#### Prerequisites

インポートしたいアプリケーションを閲覧できるアカウントに対して、Veracode の **API 認証情報**を生成します: Veracode プラットフォームでアカウントメニューを開き、**API Credentials** から **Generate API Credentials** を選択します([Veracode API 認証情報の管理](https://docs.veracode.com/r/c_api_credentials3)を参照)。**API ID** と **API Secret Key** の両方をコピーしてください — シークレットは一度しか表示されません。

#### Connector Mappings

1. **Location** フィールドに Veracode API のベース URL を入力します: `https://api.veracode.com`(商用リージョン)、`https://api.veracode.eu`(欧州リージョン)、または `https://api.veracode.us`(米国連邦リージョン)です。
2. **API ID** フィールドに API ID を入力します。
3. **Secret** フィールドに API シークレットキーを入力します。
4. 必要に応じて、**Minimum Severity** を設定してインポートする検出事項を絞り込みます。

各 Veracode アプリケーションは Record になります。**open**(未解決)の検出事項のみがインポートされるため、再インポートを行うと、Veracode が解決済みと報告した検出事項はクローズされます。
