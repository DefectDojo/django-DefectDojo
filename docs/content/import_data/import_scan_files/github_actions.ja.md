---
title: GitHub Actions からのインポート
description: 公式の DefectDojo アクションを使用して、GitHub Actions のワークフローからスキャン結果をインポートします
weight: 3
---

公式の [DefectDojo アクション](https://github.com/DefectDojo/defectdojo-action)は、GitHub Actions のワークフローからスキャンレポートを DefectDojo にインポートします。DefectDojo Pro とオープンソース版の両方で動作し、SARIF を含む DefectDojo がサポートするすべてのレポート形式を読み取ります。

実行のたびに同じテストへ再インポートするため、スキャナーが報告しなくなった検出事項はクローズされ、各検出事項はその履歴を保持します。アクションはビルド、ブランチ、コミット、リポジトリをテストに記録し、指定した重要度の検出事項がアクティブなまま残っている場合には、ワークフローのステップを失敗させることもできます。

## 始める前に

1. アセットへのインポートが可能なユーザー(アクションにアセットの作成を許可する場合は、アセットを作成できるユーザー)の API v2 キーを作成します。キーはユーザーメニューの **API v2 Token** にあります。
2. GitHub リポジトリで、**Settings > Secrets and variables > Actions** にキーを `DEFECTDOJO_API_TOKEN` という名前のシークレットとして追加します。

## ワークフローにアクションを追加する

スキャナーを実行し、そのレポートをアクションに渡します。

```yaml
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

`scan-type` は、DefectDojo に一覧表示されているレポート形式の名前です(例: `SARIF`、`Trivy Scan`、`Semgrep JSON Report`)。すべての名前については[サポートされているツール](/supported_tools/)を参照してください。

## 検出事項の保存先

指定しない場合、アクションはリポジトリに由来する名前を使用し、まだ存在しないものは作成します。

| DefectDojo のオブジェクト | デフォルト | 入力 |
| --- | --- | --- |
| 組織(製品タイプ) | リポジトリの所有者 | `organization-name` または `product-type-name` |
| アセット(製品) | リポジトリ名 | `asset-name` または `product-name` |
| エンゲージメント | ブランチ名 | `engagement-name` |
| テスト | スキャンタイプ | `test-title` |

1つのエンゲージメントに同じスキャンタイプのレポートが複数ある場合は、それぞれに専用の `test-title` を指定して、各再インポートが自身のテストを見つけられるようにしてください。

### ブランチ、プルリクエスト、タグ

ブランチごとに専用のエンゲージメントが作成されるため、プルリクエストのスキャンがデフォルトブランチの検出事項をクローズしたり再オープンしたりすることはありません。プルリクエストにはそのソースブランチが使用され、タグにはタグ名が使用され、マージキューではベースブランチごとに1つのエンゲージメントが使用されます。

デフォルトブランチ以外のためにアクションが作成するエンゲージメントは、そのエンゲージメント内でのみ重複排除を行います(**このエンゲージメント内のみで重複排除**)。これがないと、ブランチで最初に検出された検出事項によって、デフォルトブランチにある同じ検出事項が重複としてマークされてしまいます。ブランチのエンゲージメントはブランチがマージされた後も DefectDojo に残るため、アセットの件数に含めたくない場合は、デフォルトブランチでのみインポートを実行してください。

## ビルドを失敗させる

`fail-on` に `low`、`medium`、`high`、`critical` のいずれかを設定すると、インポート後にテストにその重要度以上のアクティブな検出事項がある場合にステップが失敗します。重複は数に含まれません。ジョブサマリーには、重要度別の件数とテストへのリンクが表示されます。

## Pro 機能

DefectDojo Pro では、アクションで次のことも行えます。

- アセットに設定されたコネクターに新しい検出事項をプッシュする(`push-to-connector: true`)。
- 大きなレポートをバックグラウンドでインポートする(`background-import: true`)。アクションは、件数を報告したり `fail-on` を適用したりする前に、テストの処理が完了するまで待機します。
- アセットの名前が変更されたか移動された場合に警告し、ワークフロー内の名前を更新できるようにする。

オープンソース版では、これらの入力は警告とともにスキップされ、インポート自体は実行されます。代わりにステップを失敗させたい場合は、`strict: true` を設定してください。

## フォークからのプルリクエスト

GitHub は、フォークからのプルリクエストで実行されるワークフローにはシークレットを渡さないため、アクションはその場合に認証できません。インポートは `push` で実行するか、同じリポジトリ内のブランチからのプルリクエストで実行してください。これを回避するために `pull_request_target` を使用しないでください。信頼できないコードをチェックアウトしながら、シークレットを使って実行されてしまいます。

## すべての入力と出力

[アクションの README](https://github.com/DefectDojo/defectdojo-action#inputs) に、すべての入力と出力が一覧されています。ほとんどの入力は、[API からのインポート](/import_data/import_scan_files/api_pipeline_modelling/)で説明している **/reimport** エンドポイントのフィールドに対応しています。
