---
title: "Black Duck"
description: "DefectDojo で Black Duck の Upstream Connector をセットアップする方法"
weight: 26
audience: pro
---
Black Duck コネクタは、Black Duck(Synopsys / Black Duck)Hub インスタンスから**ソフトウェア構成分析(SCA)**の検出事項をインポートします。DefectDojo はインスタンス内のすべてのプロジェクトを検出し、**プロジェクト**ごとにレコードを作成します。プロジェクトの検出事項は、選択されたバージョンの脆弱な BOM コンポーネントから取得されます。

#### Prerequisites

インポートしたいプロジェクトを閲覧できるユーザーの Black Duck **API トークン**が必要です。Black Duck でユーザーメニュー \> **My Access Tokens** \> **Create New Token** を開き、(少なくとも)読み取りアクセスを付与して、表示されたトークンをコピーしてください(表示されるのは一度きりです)。コネクタは各同期時にこのトークンを短命なベアラートークンと交換します。コネクタの secret フィールド以外に平文で保存されることはありません。

#### Connector Mappings

1. **Location** フィールドに Black Duck の hub URL を入力します。例: `https://your-company.app.blackduck.com`。
2. **Secret** フィールドに API トークンを入力します。
3. 必要に応じて、インポートする検出事項を制限するために **Minimum Severity** を設定します。

各 Black Duck プロジェクトが 1 件のレコードになります。デフォルトでは、コネクタはプロジェクトの**リリース済み**バージョン(存在しない場合は最初のバージョンにフォールバック)をインポートします。そのバージョンの脆弱な BOM コンポーネントごとに、`{vulnerability} in {component}:{version}` というタイトルの検出事項が作成されます。

このコネクタは、ファイルベースの Black Duck パーサーとは別物です。このコネクタの検出事項は専用の **Black Duck - Connectors Import** スキャンタイプを使用します。
