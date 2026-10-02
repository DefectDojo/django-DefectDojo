---
title: 言語とコード行数
description: clocツールを使用して製品の言語構成データをインポートする
weight: 3
audience: opensource
aliases:
- /ja/en/open_source/languages
---

DefectDojoでは、[cloc](https://github.com/AlDanial/cloc)(Count Lines of Code)ツールのレポートをAPI経由でインポートすることで、製品のプログラミング言語とコード行数の内訳を表示できます。

## Generating the cloc Report

`--json`フラグを付けて`cloc`をコードベースに対して実行し、正しい形式のJSONファイルを生成します:

```bash
cloc --json /path/to/your/project > cloc-report.json
```

## Importing via the API

JSONレポートをAPI経由でDefectDojoにアップロードします。インポート時には、製品の既存の言語データはすべて新しいファイルの内容に置き換えられます。

インポートエンドポイントについては、[DefectDojo API v2 docs](../api-v2-docs/)に記載されています。

## Viewing Results

インポート後、言語の内訳は製品詳細ページの左側に表示され、各言語とその行数が示されます。各言語の色は`Language_Type`テーブルのエントリーで定義されており、GitHubのデータで事前に設定されています。

## Updating Language Colors

GitHubは新しい言語が登場するたびに、定期的に言語の色を更新しています。最新の色データを取得するには、次の管理コマンドを実行します:

```bash
./manage.py import_github_languages
```

これは[ozh/github-colors](https://github.com/ozh/github-colors)から読み込み、新しい言語を追加したり、既存の色を更新したりします。
