---
title: APIによるレポートの自動化
description: DefectDojo Pro REST APIを使用してテーマ、ブロック、テンプレートを作成し、レポートを実行して結果をダウンロードします
draft: false
audience: pro
weight: 21
slug: report-builder-api
---

<span style="background-color:rgba(242, 86, 29, 0.3)">注: Report Builder REST API(レポートテーマ、ブロック、テンプレート、生成されたレポート)はDefectDojo Proの機能であり、現在ベータ版です。</span>

Report Builder REST APIを使うと、[Report Builder UI](../report-builder/)で手作業により組み立てるのと同じテーマ、ブロック、テンプレートを自動化できます。さらに一歩進んで、テンプレートを**実行**し、完成したPDFまたはHTMLを**ダウンロード**することも可能です。このガイドでは、認証、フィールドとフィルターの語彙の把握、構成要素の作成、そしてレポートの生成と取得という一連の流れを最初から最後まで説明します。

> **簡易な検出事項エクスポートをお探しですか?** テーマ、ブロック、テンプレートを設定せずに、検出事項の単純な一覧をJSON、HTML、CSV、Excelとして取得したいだけなら、[Generating Reports](/automation/api/api-v2-docs/#generating-reports)に記載されているよりシンプルな `generate_report/` エンドポイントを使用してください。このページで説明するReport Builder APIは、デザインされた複数セクション構成のレポートを構築するためのものです。

## 認証

すべてのリクエストは、`Authorization` ヘッダーに `Token` プレフィックス(`Bearer` ではありません)を付けて送信する個人用APIトークンで認証します。

DefectDojo Pro UIの **User Settings → API v2 Key** からトークンを取得してください。シェルの履歴やコミット済みスクリプトに残らないよう、環境変数に保存します。

```bash
export DD_IMPORTER_DOJO_API_TOKEN="YOUR_API_TOKEN"
```

すべての呼び出しのベースURLは、インスタンスのURLに `/api/v2` を付加したものです。

```text
https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2
```

必須ヘッダー:

| ヘッダー | 値 | タイミング |
|--------|-------|------|
| `Authorization` | `Token YOUR_API_TOKEN` | すべてのリクエスト |
| `Accept` | `application/json` | すべてのリクエスト |
| `Content-Type` | `application/json` | JSONボディを伴う `POST` / `PATCH` |

認証済みリクエストの最小例は次のとおりです。

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_themes/"
```

一覧取得エンドポイントは、`limit` と `offset` のクエリパラメータでページネーションされます。

> **⚠️ セキュリティに関する注意:** あなたのAPIトークンは、あなたのDefectDojoデータへのフルアクセス権を与えます。チャット、スクリーンショット、チケット、コミット済みファイルに絶対に貼り付けないでください。環境変数から読み込み、万一漏洩した場合はローテーションし、可能な限りサービスアカウントにトークンのスコープを限定してください。

## レポートAPIの全体像

Report Builder APIは4つのリソースで構成されています。それぞれが標準の一覧取得(`GET`)、作成(`POST`)、個別取得(`GET {id}/`)、更新(`PATCH {id}/`)、削除(`DELETE {id}/`)操作に加え、いくつかのカスタムアクションをサポートします。

| リソース | パス | 内容 | カスタムアクション |
|----------|------|------------|----------------|
| テーマ | `/report_themes/` | 色、フォント、ヘッダー/フッター画像、ページ番号 | — |
| ブロック | `/report_blocks/` | コンテンツの1つの単位: 表紙、表、または詳細セクション | `field_options/`、`preview/`、`{id}/preview/`、`{id}/duplicate/` |
| テンプレート | `/report_templates/` | ブロックの順序付きリストとテーマ | `{id}/duplicate/` |
| 生成されたレポート | `/generated_reports/` | ダウンロード可能なファイルを生成するテンプレートの実行 | `{id}/download/` |

必要な語彙を把握するのに役立つエンドポイントがさらに2つあります。

| エンドポイント | 目的 |
|----------|---------|
| `GET /report_blocks/field_options/` | 各モデルの有効な列フィールドパスと並び替えオプション |
| `GET /oa3/schema/?format=json` | 有効なフィルター名を調べるために使う完全なOpenAPIスキーマ |

## ステップ1: 語彙を把握する

ブロックの中で推測すると間違えやすいものが2つあります。それは、列挙する**カラムフィールド**と、適用する**フィルター**です。APIはこの両方について信頼できる情報源を提供します。まずこれらを取得してから、サーバーが実際に受け付ける内容に沿って構築してください。

### カラムフィールドと並び替え

`field_options` は、テーブル形式ブロックまたは詳細ブロックに配置できるすべてのモデルについて、有効な `fields`(カラムパス)と `ordering_fields` を返します。

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_blocks/field_options/"
```

レスポンスは次のような形になります(一部省略):

```json
{
  "fields": {
    "finding": [
      {"path": "title", "label": "Title"},
      {"path": "severity", "label": "Severity"},
      {"path": "age_days", "label": "Age (days)"}
    ],
    "asset": [ ... ]
  },
  "ordering_fields": {
    "finding": [ ... ]
  }
}
```

ブロックの `fields` リストには、ここで返された `path` の値だけを使用してください。一部のパスは長文やmarkdown形式であり、狭いテーブル列ではなく**詳細**ブロック向けに意図されています。`field_options` が正式な一覧であるため、網羅的なセットをハードコーディングするのではなく、これに照らして確認してください。

### スキーマからフィルター名を調べる

ブロックのフィルターは `filter_entries` に格納され、各エントリは `{field, value}` のペアです。有効な `field` 名は、対象エンティティのRESTエンドポイントの **GETクエリパラメータ名** であり、UIに表示されるラベルでは*ありません*。これはOpenAPIスキーマを読むことで調べられます。

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/oa3/schema/?format=json" \
  > schema.json
```

次に、フィルター対象のエンティティのGETパラメータを読みます。検出事項の場合は、`paths` → `/api/v2/findings/` → `get` → `parameters` を参照してください。類似のエンドポイントとして、**アセット**(旧称:製品)用の `/api/v2/assets/`、**組織**(旧称:製品タイプ)用の `/api/v2/organizations/`、`/api/v2/engagements/`、`/api/v2/tests/`、`/api/v2/test_types/`、`/api/v2/risk_acceptance/` があります。各パラメータの `name` が有効なフィルター `field` です。

> **💡 ヒント:** DefectDojo Proでは、**アセット** はかつて **製品** と呼ばれ、**組織** はかつて **製品タイプ** と呼ばれていました。検出事項のフィルターフィールドパスの基盤部分は、エンティティが現在アセットおよび組織になった後も、旧来の `product` という表記のままです(例: `test__engagement__product`)。

> **🔑 重要:** サーバーは、そのモデルの実際のGETパラメータでない `field` を持つ `filter_entry` を**黙って破棄します**。エラーは発生しません。フィルターは単に保存されたブロックに存在しないだけです。ブロックを作成した後は必ずGETで取得し直し、返された `filter_entries` を送信内容と比較してください。

### よく使うフィルターフィールド

以下の表は、検証済みで有用性の高いフィルターの一覧です。値はすべて**単一の文字列**として送信します。真偽値はリテラル文字列の `"true"` / `"false"` です。

**検出事項のフィルター**

| フィールド | 値の例 | 備考 |
|-------|---------------|-------|
| `active` | `"true"` | 真偽値の文字列 |
| `verified` | `"true"` | 真偽値の文字列 |
| `is_mitigated` | `"false"` | 真偽値の文字列 |
| `risk_accepted` | `"false"` | 真偽値の文字列 |
| `duplicate` | `"false"` | 真偽値の文字列 |
| `false_p` | `"false"` | 真偽値の文字列 |
| `out_of_scope` | `"false"` | 真偽値の文字列 |
| `severity` | `"Critical"` | 単一の値のみ — カンマ区切りは**不可**。深刻度ごとにブロックを分けてください。 |
| `known_exploited` | `"true"` | 真偽値の文字列 |
| `ransomware_used` | `"true"` | 真偽値の文字列 |
| `outside_of_sla` | `"1"` | 真偽値ではなく**数値**の文字列 |
| `priority_min` | `"800"` | `_greater_than` ではなく `_min`/`_max` を使用 |
| `priority_max` | `"1000"` | `_min`/`_max` を使用 |
| `tag` | `"DR"` | タグ1つ |
| `tags` | `"kev,pci"` | いずれか一致(列挙したタグのいずれかに一致) |
| `tags__and` | `"kev,pci"` | すべて一致(列挙したすべてのタグに一致する必要がある) |
| `test__engagement__product` | `"42"` | アセットID(アセットは旧称:製品) |
| `test__engagement__product__prod_type` | `"3"` | 組織ID(旧称:製品タイプ) |
| `cve` | `"CVE-2024-12345"` | |
| `cwe` | `"79"` | |
| `date_after` | `"2025-12-31"` | |
| `date_before` | `"2025-12-31"` | |
| `planned_remediation_date_before` | `"2025-12-31"` | |

**アセットのフィルター**(アセットはかつて製品と呼ばれていました。これらは `/api/v2/assets/` のパラメータです)

| フィールド | 値の例 | 備考 |
|-------|---------------|-------|
| `business_criticality` | `"very_high"` | |
| `internet_accessible` | `"true"` | 真偽値の文字列 |
| `lifecycle` | `"production"` | |
| `platform` | `"web"` | |
| `tag` | `"pci"` | タグ1つ |

**リスク受容のフィルター**

| フィールド | 値の例 | 備考 |
|-------|---------------|-------|
| `decision` | `"Accept (Transfer)"` | |
| `owner` | `"7"` | ユーザーID |
| `expiration_date_before` | `"2025-12-31"` | このモデルには `tag` フィルターは存在しません |

**エンゲージメント**、**テスト**、**テストタイプ**、**組織**のブロックについては、上記の方法でスキーマからGETパラメータを直接読み取ってください。有用性の高いものとして、テストの `engagement__product` と `status`、テストタイプの `name` がありますが、依存する前に必ず `schema.json` で正確な名前を確認してください。

> **⚠️** 次のような旧式・UI風の名前は**黙って破棄される**ため使用してはいけません: `status_any`、`priority_greater_than`、`severity__in`、`mitigated_within_sla`、および**カンマ区切りの `severity`** 値(例: `"Critical,High"`)。代わりにスキーマにある実際のクエリパラメータ名を使用し、複数深刻度が必要な場合は別々のブロックに分けてください。

> **🔑 重要:** `filter_entries` を含む `PATCH` は**リスト全体を置き換えます**。マージは行われません。更新のたびに希望するフィルターの完全なセットを送信してください。そうしないと、省略した分が失われます。

## ステップ2: テーマ、ブロック、テンプレートを作成する

依存関係の順序に従って構成要素を作成します: まず**テーマ**、次に**ブロック**、最後に両方を参照する**テンプレート**です。

### テーマを作成する

色は7文字の16進数文字列です。省略したフィールドはデフォルト値になります(primary `#1e3a5f`、secondary `#4a90a4`、accent `#e67e22`、text `#333333`、background `#ffffff`)。

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_themes/" \
  -d '{
    "name": "Quarterly Review Theme",
    "primary_color": "#1e3a5f",
    "secondary_color": "#4a90a4",
    "accent_color": "#e67e22",
    "text_color": "#333333",
    "background_color": "#ffffff",
    "footer_text": "Confidential — Internal Use Only",
    "show_page_numbers": true
  }'
```

レスポンスには新しいテーマの `id` が含まれます。ヘッダー画像とフッター画像は任意で、マルチパートフォームフィールド(`header_image` / `footer_image`)としてアップロードします。上記のJSON例ではこれらを省略しています。

### ブロックを作成する

ブロックは `name`、`block_type`、およびそれに対応する構成オブジェクトを持ちます。サポートされる `block_type` の値は `stock`、`tabular`、`detail` です。(データモデル上は `chart` タイプも存在しますが、APIではまだ公開されていません。)

**スタティックな表紙。** stockブロックは固定コンテンツを保持します。`stock_type` は `cover_page`、`table_of_contents`、`page_break`、`image`、`text_block` のいずれかです。

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_blocks/" \
  -d '{
    "name": "Cover Page",
    "block_type": "stock",
    "header": "Cover",
    "stock_configuration": {
      "stock_type": "cover_page",
      "title": "Quarterly Security Report",
      "subtitle": "Q4 — Active Critical Findings"
    }
  }'
```

**フィルター付きテーブル形式の検出事項ブロック。** tabularブロックは、選択したモデルの行を表示します。`model_choice` は `organization`、`asset`、`engagement`、`test`、`finding`、`test_type`、`risk_acceptance` のいずれか1つです。`fields` は `field_options` から取得し(各 `path` を確認してください)、`filter_entries` で行の範囲を絞り込みます。

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_blocks/" \
  -d '{
    "name": "Active Critical Findings",
    "block_type": "tabular",
    "header": "Active Critical Findings",
    "tabular_configuration": {
      "model_choice": "finding",
      "fields": ["severity", "title", "age_days", "sla_days_remaining"],
      "ordering": "-age_days"
    },
    "filter_entries": [
      {"field": "active", "value": "true"},
      {"field": "severity", "value": "Critical"}
    ]
  }'
```

**詳細な検出事項ブロック。** detailブロックはレコードごとに1つの展開されたセクションを表示し、狭いテーブル列には向かない長文やmarkdown形式のフィールドを含めることができます。ここでも `fields` を `field_options` に照らして確認してください。

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_blocks/" \
  -d '{
    "name": "Critical Finding Detail",
    "block_type": "detail",
    "header": "Critical Findings — Detail",
    "detail_configuration": {
      "model_choice": "finding",
      "fields": ["title", "severity", "description", "mitigation"],
      "ordering": "-severity"
    },
    "filter_entries": [
      {"field": "active", "value": "true"},
      {"field": "severity", "value": "Critical"}
    ]
  }'
```

各ブロックのレスポンスには `id` が含まれます。`filter_entries` はサーバーが実際に保存した内容をそのまま返すので、送信した内容と比較してください([作成した内容を検証する](#verify-what-you-built)を参照)。

### テンプレートを作成する

テンプレートはテーマとブロックの順序付きリストを結び付けます。読み取り専用フィールドは `template_blocks` であり、作成時と更新時には `template_blocks_write` を**書き込みます**。各エントリには `order` と `block_id` が必要で、同じ `block_id` を複数回指定することもできます。

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_templates/" \
  -d '{
    "name": "Quarterly Critical Report",
    "description": "Cover page, critical findings table, then per-finding detail",
    "theme_id": 1,
    "template_blocks_write": [
      {"order": 0, "block_id": 10},
      {"order": 1, "block_id": 11},
      {"order": 2, "block_id": 12}
    ]
  }'
```

`theme_id` と各 `block_id` を、前のステップで返されたIDに置き換えてください。レスポンスにはテンプレートの `id` が含まれます。

## ステップ3: レポートを実行し、結果をダウンロードする

レポートの生成は非同期です。実行を作成し、ステータスをポーリングし、完了したらファイルをダウンロードします。

**実行を開始する。** `template_id` と、`pdf` または `html` の `file_format` をPOSTします。

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/generated_reports/" \
  -d '{
    "template_id": 5,
    "file_format": "pdf"
  }'
```

レスポンスは、`status` が `pending` に設定された新しいレポートの `id` を返します。

**ステータスをポーリングする。** レポートを取得し、`status` が終了状態に達するまで繰り返します。フローは `pending` → `processing` → `completed` です。`failed` の場合は、理由について `error_message` を確認してください。

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/generated_reports/7/"
```

**ファイルをダウンロードする。** `status` が `completed` になったら、ダウンロードエンドポイントはファイルを添付ファイルとして返します。それまでは `404` を返します。

```bash
curl -s -L \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/generated_reports/7/download/" \
  -o report.pdf
```

## まとめ: 完全なライフサイクルスクリプト

以下のスクリプトは、Python 3標準ライブラリのみを使用して(`requests` などのサードパーティパッケージなしで)一連の流れ全体を実行します。`DD_IMPORTER_DOJO_API_TOKEN` からトークンを読み取り、テーマ、3つのブロック、テンプレートを作成し、レポートを起動し、完了または失敗するまでバックオフしながらポーリングし、結果をダウンロードし、作成されたIDを `created.json` に書き込みます。

インスタンスのURLを設定して実行してください。

```bash
export DD_IMPORTER_DOJO_API_TOKEN="YOUR_API_TOKEN"
export DD_BASE_URL="https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2"
python3 build_report.py
```

```python
#!/usr/bin/env python3
"""Build and run a DefectDojo Pro report end-to-end using only the stdlib."""

import json
import os
import time
import urllib.error
import urllib.request

# --- Configuration -------------------------------------------------------
BASE_URL = os.environ.get(
    "DD_BASE_URL",
    "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2",
).rstrip("/")
TOKEN = os.environ["DD_IMPORTER_DOJO_API_TOKEN"]  # fail loudly if unset
FILE_FORMAT = "pdf"  # "pdf" or "html"


def api_request(method, path, body=None, accept_json=True):
    """Make an authenticated request. Returns parsed JSON (or raw bytes)."""
    url = f"{BASE_URL}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None

    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Authorization", f"Token {TOKEN}")
    if accept_json:
        request.add_header("Accept", "application/json")
    if data is not None:
        request.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(request) as response:
            payload = response.read()
    except urllib.error.HTTPError as error:
        # Surface the server's error body to make debugging easy.
        detail = error.read().decode("utf-8", errors="replace")
        raise SystemExit(f"{method} {path} failed ({error.code}): {detail}")

    if accept_json:
        return json.loads(payload) if payload else {}
    return payload


def main():
    created = {}

    # 1. Create a theme.
    theme = api_request("POST", "/report_themes/", {
        "name": "Quarterly Review Theme",
        "primary_color": "#1e3a5f",
        "secondary_color": "#4a90a4",
        "accent_color": "#e67e22",
        "text_color": "#333333",
        "background_color": "#ffffff",
        "footer_text": "Confidential - Internal Use Only",
        "show_page_numbers": True,
    })
    created["theme_id"] = theme["id"]
    print(f"Created theme id={theme['id']}")

    # 2. Create a stock cover page block.
    cover = api_request("POST", "/report_blocks/", {
        "name": "Cover Page",
        "block_type": "stock",
        "header": "Cover",
        "stock_configuration": {
            "stock_type": "cover_page",
            "title": "Quarterly Security Report",
            "subtitle": "Q4 - Active Critical Findings",
        },
    })
    created["cover_block_id"] = cover["id"]
    print(f"Created stock block id={cover['id']}")

    # 3. Create a tabular finding block scoped to active criticals.
    #    Confirm the chosen fields against /report_blocks/field_options/.
    table = api_request("POST", "/report_blocks/", {
        "name": "Active Critical Findings",
        "block_type": "tabular",
        "header": "Active Critical Findings",
        "tabular_configuration": {
            "model_choice": "finding",
            "fields": ["severity", "title", "age_days", "sla_days_remaining"],
            "ordering": "-age_days",
        },
        "filter_entries": [
            {"field": "active", "value": "true"},
            {"field": "severity", "value": "Critical"},
        ],
    })
    created["table_block_id"] = table["id"]
    print(f"Created tabular block id={table['id']}")

    # 4. Create a detail finding block.
    detail = api_request("POST", "/report_blocks/", {
        "name": "Critical Finding Detail",
        "block_type": "detail",
        "header": "Critical Findings - Detail",
        "detail_configuration": {
            "model_choice": "finding",
            "fields": ["title", "severity", "description", "mitigation"],
            "ordering": "-severity",
        },
        "filter_entries": [
            {"field": "active", "value": "true"},
            {"field": "severity", "value": "Critical"},
        ],
    })
    created["detail_block_id"] = detail["id"]
    print(f"Created detail block id={detail['id']}")

    # 5. Create a template binding the theme to the ordered blocks.
    #    Note: we WRITE template_blocks_write; template_blocks is read-only.
    template = api_request("POST", "/report_templates/", {
        "name": "Quarterly Critical Report",
        "description": "Cover, critical findings table, then per-finding detail",
        "theme_id": created["theme_id"],
        "template_blocks_write": [
            {"order": 0, "block_id": created["cover_block_id"]},
            {"order": 1, "block_id": created["table_block_id"]},
            {"order": 2, "block_id": created["detail_block_id"]},
        ],
    })
    created["template_id"] = template["id"]
    print(f"Created template id={template['id']}")

    # 6. Kick off a report run.
    report = api_request("POST", "/generated_reports/", {
        "template_id": created["template_id"],
        "file_format": FILE_FORMAT,
    })
    report_id = report["id"]
    created["report_id"] = report_id
    print(f"Started report id={report_id} (status={report['status']})")

    # 7. Poll until completed or failed, backing off up to 10 seconds.
    delay = 2
    while True:
        time.sleep(delay)
        report = api_request("GET", f"/generated_reports/{report_id}/")
        status = report["status"]
        print(f"  status={status}")
        if status == "completed":
            break
        if status == "failed":
            raise SystemExit(
                f"Report failed: {report.get('error_message', 'unknown error')}"
            )
        delay = min(delay + 2, 10)  # linear backoff, capped

    # 8. Download the finished file.
    content = api_request(
        "GET",
        f"/generated_reports/{report_id}/download/",
        accept_json=False,
    )
    out_name = f"report.{FILE_FORMAT}"
    with open(out_name, "wb") as handle:
        handle.write(content)
    print(f"Downloaded {out_name} ({len(content)} bytes)")

    # 9. Record the created IDs for later cleanup or reuse.
    with open("created.json", "w") as handle:
        json.dump(created, handle, indent=2)
    print("Wrote created.json")


if __name__ == "__main__":
    main()
```

## 作成した内容を検証する

無効なフィルターは黙って破棄されるため、検証は後付けの作業ではなくワークフローの一部です。

**ブロックのフィルターが残っているか確認する。** 各ブロックをGETで取得し直し、`filter_entries` をPOSTした内容と比較します。

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_blocks/11/"
```

送信したフィルターが `filter_entries` に見当たらない場合、その `field` 名がそのモデルの有効なGETパラメータではなかったということです。`schema.json` で名前を再確認してください。

**テンプレートの順序とテーマを確認する。** テンプレートをGETし、`template_blocks` が期待どおりの `order` でブロックを列挙しているか、紐付けられたテーマが一致しているかを確認します。

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_templates/5/"
```

**PATCHで破棄されたフィルターを修正する。** ブロックのフィルターを修正するには、希望する**完全な**セットをPATCHしてください。PATCHは `filter_entries` を丸ごと置き換えます。

```bash
curl -s -X PATCH \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_blocks/11/" \
  -d '{
    "filter_entries": [
      {"field": "active", "value": "true"},
      {"field": "severity", "value": "Critical"},
      {"field": "outside_of_sla", "value": "1"}
    ]
  }'
```

## 次のステップ

- 同じテーマ、ブロック、テンプレートを [Report Builder UI](../report-builder/) でインタラクティブに構築してプレビューできます。
- [Report Builder LLM integration](../report-builder-llm/) を使えば、LLMにレポート構成を組み立てさせることもできます。
