---
title: 重複排除のチューニング(オープンソース)
description: 'DefectDojo Open Sourceでの重複排除の設定: アルゴリズム、ハッシュフィールド、エンドポイント、サービス'
weight: 5
audience: opensource
aliases:
- /ja/en/working_with_findings/finding_deduplication/deduplication_tuning_os
- /ja/en/working_with_findings/finding_deduplication/deduplication_algorithms
---

DefectDojoのOpen Source版では、設定ファイルと環境変数を使用して重複排除を調整します。

関連情報: 環境変数と`local_settings.py`によるオーバーライドの詳細については、[オープンソースの設定](/get_started/open_source/configuration/)を参照してください。

## 設定可能な項目

- **パーサーごとのアルゴリズム**: Unique ID From Tool、Hash Code、Unique ID From Tool or Hash Code、Legacy(OS版のみ)のいずれかを選択します。
- **スキャナーごとのハッシュフィールド**: 各パーサーでハッシュの計算に使用するフィールドを決定します。
- **null CWEの許可**: ハッシュ計算時に、CWEが未設定/ゼロであることを許容するかどうかを制御します。
- **エンドポイントの考慮**: エンドポイントがハッシュに含まれていない場合でも、任意でエンドポイントを重複排除に使用できます。
- **常に含めるフィールド**: スキャナーごとの設定に関わらず、すべてのハッシュにフィールド(例: `service`)を追加します。

## 主要な設定項目(デフォルト値を表示)

デフォルト値はすべて`dojo/settings/settings.dist.py`で定義されています。環境変数または`local_settings.py`で上書きできます。

### パーサーごとのアルゴリズム

- 設定項目: `DEDUPLICATION_ALGORITHM_PER_PARSER`
- パーサーごとの値: `unique_id_from_tool`、`hash_code`、`unique_id_from_tool_or_hash_code`、`legacy`のいずれか
- 例(環境変数のJSON文字列):

```bash
DD_DEDUPLICATION_ALGORITHM_PER_PARSER='{"Trivy Scan": "hash_code", "Veracode Scan": "unique_id_from_tool_or_hash_code"}'
```

### スキャナーごとのハッシュフィールド

- 設定項目: `HASHCODE_FIELDS_PER_SCANNER`
- OS版でのTrivyのデフォルト例:

```startLine:endLine:dojo/settings/settings.dist.py
1318:1321:dojo/settings/settings.dist.py
    "Trivy Operator Scan": ["title", "severity", "vulnerability_ids", "description"],
    "Trivy Scan": ["title", "severity", "vulnerability_ids", "cwe", "description"],
    "TFSec Scan": ["severity", "vuln_id_from_tool", "file_path", "line"],
    "Snyk Scan": ["vuln_id_from_tool", "file_path", "component_name", "component_version"],
```

- オーバーライドの例(環境変数のJSON文字列):

```bash
DD_HASHCODE_FIELDS_PER_SCANNER='{"ZAP Scan":["title","cwe","severity"],"Trivy Scan":["title","severity","vulnerability_ids","description"]}'
```

### スキャナーごとのnull CWEの許可

- 設定項目: `HASHCODE_ALLOWS_NULL_CWE`
- パーサーごとに、ハッシュ計算においてnull/ゼロのCWEを許容するかどうかを制御します。Falseに設定されており、かつ検出事項の`cwe = 0`である場合、その検出事項のハッシュはレガシーの計算方法にフォールバックします。

### ハッシュに常に含まれるフィールド

- 設定項目: `HASH_CODE_FIELDS_ALWAYS`
- デフォルト: `["service"]`
- 影響: すべてのスキャナーのハッシュに追加されます。ここから`service`を削除すると、全体的にハッシュへ影響しなくなります。

```startLine:endLine:dojo/settings/settings.dist.py
1464:1466:dojo/settings/settings.dist.py
# Adding fields to the hash_code calculation regardless of the previous settings
HASH_CODE_FIELDS_ALWAYS = ["service"]
```

### エンドポイントベースの重複排除(オプション)

- 設定項目: `DEDUPE_ALGO_ENDPOINT_FIELDS`
- デフォルト: `["host", "path"]`
- 目的: エンドポイントがハッシュフィールドに含まれていない場合でも、重複排除のために最低限のエンドポイントの一致を要求できます。リストが空`[]`の場合、重複排除の処理でエンドポイントは無視されます。

```startLine:endLine:dojo/settings/settings.dist.py
1491:1499:dojo/settings/settings.dist.py
# Allows to deduplicate with endpoints if endpoints is not included in the hashcode.
# Possible values are: scheme, host, port, path, query, fragment, userinfo, and user.
# If a finding has more than one endpoint, only one endpoint pair must match to mark the finding as duplicate.
DEDUPE_ALGO_ENDPOINT_FIELDS = ["host", "path"]
```

## エンドポイント: チューニング方法

エンドポイントは、次の2つの仕組みを通じて重複排除に影響を与える可能性があります。

1) パーサーの`HASHCODE_FIELDS_PER_SCANNER`に`endpoints`を含める。この場合、エンドポイントはハッシュの一部となり、そのパーサーのハッシュ規則に従って完全に一致する必要があります。
2) エンドポイントがハッシュフィールドに含まれていない場合は、`DEDUPLE_ALGO_ENDPOINT_FIELDS`を使用して比較対象の属性を指定します。例:
   - `[]`: 重複排除においてエンドポイントは無視されます。
   - `["host"]`: いずれかのエンドポイントのペアがホストで一致した場合、検出事項は重複排除されます。
   - `["host", "port"]`: いずれかのエンドポイントのペアがホストとポートの両方で一致した場合、検出事項は重複排除されます。

注記:

- Legacyアルゴリズムでは、静的な検出事項と動的な検出事項でエンドポイントの一致規則が異なります(詳細はアルゴリズムのページを参照してください)。`DEDUPLE_ALGO_ENDPOINT_FIELDS`設定はhash-codeの処理経路に適用されるものであり、Legacyアルゴリズム自体の内部ロジックには適用されません。
- `unique_id_from_tool`(ID方式)による一致判定では、重複排除の判断にエンドポイントは考慮されません。

## serviceフィールド: 重複排除と再インポート

- デフォルトの`HASH_CODE_FIELDS_ALWAYS = ["service"]`では、`service`フィールドがハッシュに追加されます。それ以外の点では同一でも`service`の値が異なる2つの検出事項は、ハッシュベースの処理経路では重複排除されません。
- UI/API経由でのインポート中、`Service`の入力値がパーサーから提供されたサービス名を上書きできます。この値を変更するとハッシュも変わり、重複排除の挙動や再インポート時のマッチングに影響する可能性があります。
- サービスに依存しない重複排除を行いたい場合は、`HASH_CODE_FIELDS_ALWAYS`から`service`を削除するか、インポート時に`Service`フィールドを空欄のままにしてください。

## 重複排除の設定変更後

アルゴリズムやハッシュの計算方法を変更した後は、新しいマッチングの挙動が既存データ全体に一貫して適用されるようにするため、対象のパーサー/テストタイプについて**ハッシュを再計算する**必要があります。

注記: ハッシュの再計算は、大規模なインスタンスでは長い待ち時間につながる可能性があります。それを踏まえてメンテナンスの時間枠を計画してください。

- 重複排除の設定変更(例: `HASHCODE_FIELDS_PER_SCANNER`、`HASH_CODE_FIELDS_ALWAYS`、`DEDUPLICATION_ALGORITHM_PER_PARSER`)は、自動的に既存データへ遡って適用されることはありません。既存の検出事項を再評価するには、以下のmanagementコマンドを実行する必要があります。

### 既存データの積み残しに対する重複排除の実行

重複排除の設定を最初に構成したとき(または後で変更したとき)、変更前にインポートされた検出事項は、明示的に重複排除を再実行するまで古いハッシュのままとなります。既存の検出事項を再ハッシュ化・再評価するには、`dedupe` managementコマンドを使用します。

uwsgiコンテナ内で実行します。例(ハッシュコードのみを計算し、重複排除は行わない場合):

```bash
docker compose exec uwsgi /bin/bash -c "python manage.py dedupe --hash_code_only"
```

すべてのパーサーについて**ハッシュを再計算し重複排除を実行する**場合(「重複排除を有効にしたばかりで積み残しを整理したい」という典型的なワークフロー):

```bash
docker compose exec uwsgi /bin/bash -c "python manage.py dedupe"
```

特定のパーサーのみを対象にする場合:

```bash
docker compose exec uwsgi /bin/bash -c "python manage.py dedupe --parser 'Trivy Scan'"
```

ヘルプ/使用方法:
```
options:
  --parser PARSER       List of parsers for which hash_code needs recomputing
                        (defaults to all parsers)
  --hash_code_only      Only compute hash codes
  --dedupe_only         Only run deduplication
  --dedupe_sync         Run dedupe in the foreground, default false
```

重複排除をCeleryに投入する場合(`--dedupe_sync`を付けない場合)は、結果を評価する前にタスクが完了するまで時間を確保してください。大規模なインスタンスではこれにかなりの時間がかかることがあるため、Celeryワーカーのログを監視して進捗を確認してください。

## 設定を行う場所

- デプロイ環境では環境変数の使用を推奨します。ローカル開発や高度なオーバーライドを行う場合は`local_settings.py`を使用してください。
- 環境変数の設定方法やローカルでのオーバーライドの設定方法の詳細については、`configuration.md`を参照してください。

### トラブルシューティング

重複排除のトラブルシューティングには、以下のツールを利用できます。

- `dojo.specific-loggers.deduplication`カテゴリのログ出力を確認します。これはクラスに依存しないロガーで、検出事項の処理時に重複排除のプロセスと設定に関する詳細を出力します。
- `ID`フィールドまたは`Status`列にカーソルを合わせることで、`unique_id_from_tool`と`hash_code`の値を確認できます。

![検出事項の表示ページにおけるUnique ID from ToolとHash Code](images/hash_code_id_field.png)

![検出事項一覧のStatus列におけるUnique ID from ToolとHash Code](images/hash_code_status_column.png)
