---
title: "Wazuh"
description: "DefectDojo で Wazuh の Upstream Connector をセットアップする方法"
weight: 140
audience: pro
---
Wazuh コネクタは、Wazuh Indexer(OpenSearch)を使用して脆弱性の検出事項を取得します。Wazuh 4.8 以降では、検出された CVE は Wazuh サーバー API ではなく Indexer に保存されるため、このコネクタは `wazuh-states-vulnerabilities-*` インデックスから直接それらを読み取ります。

DefectDojo は Wazuh エージェント(エンドポイント)ごとに Record を作成し、そのエージェントで検出された CVE をスケジュールに基づいて検出事項としてインポートします。

#### Prerequisites

以下が必要です。

* ポートを含む Wazuh Indexer のベース URL(Indexer はデフォルトでポート 9200 で待ち受けます)。DefectDojo は Indexer に直接接続するため、このエンドポイントは DefectDojo から到達可能である必要があります。セルフマネージド環境では、これは Wazuh Indexer を実行しているホストです。Wazuh Cloud の場合は、Wazuh Cloud コンソールに表示される Indexer エンドポイントを使用してください。これは Wazuh ダッシュボードの URL とは別のものです。
* `wazuh-states-vulnerabilities-*` インデックスへの読み取りアクセス権を持つ Indexer のユーザーとパスワード。DefectDojo 専用のユーザーを作成することをお勧めします。

脆弱性状態インデックスにデータが投入されるよう、Wazuh で脆弱性検出を有効にしておく必要があります。詳細については、[Wazuh 脆弱性検出ドキュメント](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/index.html)を参照してください。

#### Connector Mappings

1. **Location** フィールドに、スキームとポートを含む Wazuh Indexer のベース URL を入力します。例: `https://your-indexer.example.com:9200`。末尾にパスを含めないでください。DefectDojo が検索パスを自動的に構築します。
2. **Username** フィールドに Indexer のユーザー名を入力します。
3. **Password** フィールドに Indexer のパスワードを入力します。
4. 必要に応じて、**Minimum Severity** を設定してインポートする検出事項を絞り込みます。選択した深刻度を下回る検出事項はインポートされません。
