---
title: GitHub Actions からのインポート
description: 公式の DefectDojo アクションを使用して、GitHub Actions のワークフローからスキャン結果をインポートします
weight: 3
---

公式の [DefectDojo アクション](https://github.com/DefectDojo/defectdojo-action)は、GitHub Actions のワークフローからスキャンレポートを DefectDojo にインポートします。DefectDojo Pro とオープンソース版の両方で動作し、SARIF を含め、DefectDojo がサポートするすべてのレポート形式を読み取ります。

実行のたびに同じテストへ再インポートされるため、スキャナーが報告しなくなった検出事項はクローズされ、各検出事項は履歴を保持します。このアクションは、ビルド、ブランチ、コミット、リポジトリをテストに記録し、選択した重大度の検出事項がアクティブなまま残っている場合には、ワークフローのステップを失敗させることもできます。

## 始める前に

1. アセットにインポートできる(アクションにアセットの作成を許可する場合は、作成もできる)ユーザーの API v2 キーを作成します。キーはユーザーメニューの **API v2 Token**(オープンソース版の UI では **API v2 Key**)にあります。
2. GitHub リポジトリの **Settings > Secrets and variables > Actions** で、そのキーを `DEFECTDOJO_API_TOKEN` という名前のシークレットとして追加します。

## ワークフローにアクションを追加する

スキャナーを実行し、そのレポートをアクションに渡します。

```yaml
name: Security scan
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - name: Scan
        uses: aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25 # v0.36.0
        with:
          scan-type: fs
          format: json
          output: trivy.json
      - name: Import into DefectDojo
        uses: DefectDojo/defectdojo-action@v1
        with:
          defectdojo-url: https://defectdojo.example.com
          api-token: ${{ secrets.DEFECTDOJO_API_TOKEN }}
          file: trivy.json
          scan-type: Trivy Scan
          fail-on: critical
```

`scan-type` は、DefectDojo が一覧に表示するレポート形式の名前です(例: `SARIF`、`Trivy Scan`、`Semgrep JSON Report`)。すべての名前については[サポートされているツール](/supported_tools/)を参照してください。

## 検出事項の保存先

指定しない場合、アクションはリポジトリに由来する名前を使用し、まだ存在しないものは作成します。

| DefectDojo のオブジェクト | デフォルト | 入力 |
| --- | --- | --- |
| 組織 (製品タイプ) | リポジトリの所有者 | `organization-name` または `product-type-name` |
| アセット (製品) | リポジトリ名 | `asset-name` または `product-name` |
|エンゲージメント| ブランチ名 | `engagement-name` |
| テスト | スキャンタイプ | `test-title` |

1つのエンゲージメントに同じスキャンタイプのレポートが複数ある場合は、それぞれに専用の `test-title` を指定してください。そうすると、各再インポートが自身のテストを見つけられます。

### ブランチ、プルリクエスト、タグ

各ブランチには専用のエンゲージメントが作成されるため、プルリクエストのスキャンがデフォルトブランチの検出事項をクローズしたり再オープンしたりすることはありません。プルリクエストにはソースブランチが、タグにはタグ名が使用され、マージキューではベースブランチごとに1つのエンゲージメントが使用されます。

デフォルトブランチ以外のためにアクションが作成するエンゲージメントは、そのエンゲージメント内でのみ重複排除を行います(**このエンゲージメント内のみで重複排除**)。これを行わないと、ブランチで最初に検出された検出事項によって、デフォルトブランチ側のコピーが重複としてマークされてしまいます。`engagement-name` または `deduplication-on-engagement` を自分で設定すると、この動作はオフになるため、名前を付けたエンゲージメントは通常どおりアセット全体で重複排除されます。ブランチのエンゲージメントは、ブランチがマージされた後も DefectDojo に残ります。アセットの件数に含めたくない場合は、デフォルトブランチでのみインポートを実行してください。

## ビルドを失敗させる

インポート後にテストにその重大度以上のアクティブな検出事項がある場合にステップを失敗させるには、`fail-on` を `low`、`medium`、`high`、`critical` のいずれかに設定します。重複はカウントされません。ジョブのサマリーには、重大度別の件数とテストへのリンクが表示されます。

## Pro の機能

DefectDojo Pro では、このアクションで次のこともできます。

- アセットに設定されたコネクターに新しい検出事項をプッシュする(`push-to-connector: true`)。
- 大きなレポートをバックグラウンドでインポートする(`background-import: true`)。アクションは、件数を報告したり `fail-on` を適用したりする前に、テストの処理が完了するまで待機します。
- アセットの名前が変更された場合や移動された場合に警告し、ワークフロー内の名前を更新できるようにする。

オープンソース版では、`push-to-connector` と `background-import` は警告とともにスキップされ、インポート自体は実行されます。代わりにステップを失敗させるには、`strict: true` を設定します。

## フォークからのプルリクエスト

GitHub は、フォークからのプルリクエストで実行されるワークフローにはシークレットを渡さないため、アクションは認証できず、ステップが失敗します。インポートを `push` で実行するか、フォークからのプルリクエストではスキップしてください。

```yaml
      - name: Import into DefectDojo
        if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository
        uses: DefectDojo/defectdojo-action@v1
```

これを回避するために `pull_request_target` を使用しないでください。信頼できないコードをチェックアウトしながら、シークレットを使って実行されることになります。

## すべての入力と出力

すべての入力と出力は[アクションの README](https://github.com/DefectDojo/defectdojo-action#inputs) に一覧があります。ほとんどの入力は、[API からのインポート](/import_data/import_scan_files/api_pipeline_modelling/)で説明している **/reimport** エンドポイントのフィールドに対応しています。
