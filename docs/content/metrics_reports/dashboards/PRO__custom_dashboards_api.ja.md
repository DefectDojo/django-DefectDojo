---
title: APIでダッシュボードを自動化する
description: DefectDojo Pro REST APIを通じてウィジェットカタログを調べ、ダッシュボードレイアウトを作成・更新し、ウィジェットデータをレンダリングする
draft: false
audience: pro
weight: 11
slug: custom-dashboards-api
---

<span style="background-color:rgba(242, 86, 29, 0.3)">注: カスタムダッシュボードREST API（レイアウト、ウィジェットカタログ、ウィジェットデータ）はDefectDojo Proの機能です。デフォルトでは無効になっており、スーパーユーザーがCloudおよびOn-Premiseの両方のインスタンスで**設定 > 機能フラグ**からカスタムダッシュボードを有効にできます。</span>

カスタムダッシュボードREST APIを使うと、[ダッシュボードUI](../custom-dashboards/)で手動で組み立てるのと同じダッシュボードを、すべてコードから構築できます。ウィジェットカタログを調べたり、レイアウトを作成・更新したり、デフォルトを設定したり、レイアウトをチームと共有したり、DefectDojoのフィルタリングを再実装することなくウィジェットのデータをオンデマンドでレンダリングしたりできます。レイアウト機能は、ダッシュボードを構築するAIエージェントのための主要な入口として設計されているため、リクエストの形式は意図的に内省しやすい構造になっています。

本ガイドでは、認証、ウィジェットの語彙の発見、レイアウトの作成、そしてその検証とレンダリングという一連のライフサイクル全体を解説します。

## 認証

すべてのリクエストは、`Authorization`ヘッダーに`Token`プレフィックス（`Bearer`ではありません）を付けて送信する個人用APIトークンで認証します。

トークンはDefectDojo ProのUIの**ユーザー設定 → API v2キー**から取得します。シェルの履歴やコミットされたスクリプトに残らないよう、環境変数として保存してください。

```bash
export DD_IMPORTER_DOJO_API_TOKEN="YOUR_API_TOKEN"
```

すべての呼び出しのベースURLは、インスタンスに`/api/v2`を付けたものです。

```
https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2
```

必須ヘッダー:

| ヘッダー | 値 | いつ |
|--------|-------|------|
| `Authorization` | `Token YOUR_API_TOKEN` | すべてのリクエスト |
| `Accept` | `application/json` | すべてのリクエスト |
| `Content-Type` | `application/json` | JSONボディを伴う`POST` / `PATCH` |

認証付きの最小限のリクエストは次のようになります。

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_catalog/"
```

> **🔑 重要:** ダッシュボードAPI全体はカスタムダッシュボード機能に依存しています。有効になるまでは、すべてのエンドポイントが`403 Dashboards 2.0 is not enabled.`を返します。詳細は[カスタムダッシュボードの有効化](../custom-dashboards/#enabling-customizable-dashboards)を参照してください。

> **⚠️ セキュリティに関する注意:** APIトークンはDefectDojoデータへの完全なアクセス権を付与します。チャット、スクリーンショット、チケット、コミットされたファイルには絶対に貼り付けないでください。環境変数から読み込み、万一漏えいした場合はローテーションし、可能な限りサービスアカウントにトークンのスコープを限定してください。

## ダッシュボードAPIの概要

ダッシュボードAPIは、すべて`/api/v2/dashboards/`配下にある3つのリソースグループで構成されています。

| リソース | パス | 内容 | 操作 |
|----------|------|------------|------------|
| レイアウト | `/dashboards/layouts/` | 保存済みのダッシュボード（およびチーム共有テンプレート） | `GET`で一覧取得、`POST`で作成、`GET {id}/`、`PATCH {id}/`、`DELETE {id}/`、さらに`{id}/clone/`、`{id}/set_default/`、`shared/`、`for_current_user/` |
| ウィジェットカタログ | `/dashboards/widget_catalog/` | ウィジェットタイプのメニューと、各タイプの設定例 | `GET`（読み取り専用） |
| ウィジェットデータ | `/dashboards/widget_data/<action>/` | ウィジェット用のオンデマンドでレンダリングされたデータ | ウィジェットごとに21種類のアクション |

これらのエンドポイントはToken認証、Session認証、Basic認証を受け付けます。行単位の認可とデータのスコープ設定はすべて、DefectDojoの標準的なロールベースアクセス制御に従います。レイアウトを共有しても、閲覧者が見られる範囲が広がることはありません。

> **💡 ヒント:** Vue UIは、`/api/vue/dashboard_v2/`配下にあるこれらのエンドポイントの内部ミラーを呼び出します。自動化する際は、常にここで解説している安定した顧客向けの`/api/v2/dashboards/`パスを対象にしてください。

## ステップ1: 語彙を発見する

ウィジェットには、推測すると間違えやすい要素が3つあります。**ウィジェットタイプ**、（チャートの場合の）**グループ化のディメンション**、そして**フィルター**です。APIはそれぞれについて信頼できる情報源を提供します。まずこれらを取得し、サーバーが実際に受け付ける内容に基づいて構築してください。

### ウィジェットカタログ

`GET /dashboards/widget_catalog/`は、すべてのウィジェットタイプ、それが属するカテゴリー、レンダリング対象となるデータエンドポイント、そして最も便利な、出発点としてコピーできる最小限の動作確認済み`config_example`を返します。

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_catalog/"
```

レスポンスは次のような形になります（一部省略）。

```json
{
  "categories": [
    {"id": "numbers", "label": "Numbers", "description": "Single-glance metrics — counts, KPIs, gauges."},
    {"id": "charts",  "label": "Charts",  "description": "Time-series and distribution visualisations."},
    {"id": "lists",   "label": "Lists & Feeds", "description": "Ranked lists, feeds, and embedded tables."},
    {"id": "static",  "label": "Static & Utility", "description": "Notes, shortcuts, and quick actions."}
  ],
  "widgets": [
    {
      "type": "count",
      "label": "Count",
      "category": "numbers",
      "description": "Single number rendered from a filtered queryset...",
      "data_endpoints": ["/api/v2/dashboards/widget_data/count/"],
      "config_example": {
        "model": "finding",
        "filters": {"status_any": "Active", "severity": "Critical"},
        "icon": "fas fa-ban",
        "color": "danger"
      }
    },
    {
      "type": "graph",
      "label": "Graph",
      "category": "charts",
      "description": "Generic chart over any model + group-by dimension...",
      "data_endpoints": ["/api/v2/dashboards/widget_data/aggregate/"],
      "config_example": {
        "model": "finding",
        "filters": {"duplicate": "false"},
        "group_by": "severity",
        "aggregation": "count",
        "chart_type": "pie",
        "time_bucket": null,
        "limit": null,
        "stacked": false
      }
    }
  ]
}
```

ウィジェットの`type`はそのままウィジェットの`type`として使い、その`config_example`をウィジェットの`config`の出発点として使ってください。カタログには、4つのカテゴリーにまたがる26種類のウィジェットタイプが掲載されています。

### グループ化のディメンションとレコード指標

チャートおよびリーダーボードのウィジェットでは、グループ化やランキングに使える項目が、厳選された許可リストに制限されています。推測するのではなく、モデルごとにこれらを取得してください。

```bash
# Valid group_by dimensions for the Graph / Sankey / Sunburst / Top-N (aggregate) widgets:
curl -s -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_data/dimensions/?model=finding"

# Valid metrics for the Top-N widget in "records" mode:
curl -s -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_data/record_metrics/?model=product"
```

`dimensions/`は、各ディメンションの`key`（`group_by`に渡す値）、人が読める`label`、そして`kind`を返します。

```json
{
  "model": "finding",
  "dimensions": [
    {"key": "severity",  "label": "Severity",        "kind": "categorical"},
    {"key": "status",    "label": "Status",          "kind": "banded"},
    {"key": "date",      "label": "Discovered Date", "kind": "time"},
    {"key": "test_type", "label": "Test Type",       "kind": "categorical"}
  ]
}
```

`kind`は重要です。（`date`のような）`time`ディメンションでは`time_bucket`（`day`/`week`/`month`/`quarter`/`year`）も一緒に送信する必要がありますが、`categorical`または`banded`のディメンションでは不要です。`priority`フィールドは意図的にグループ化のディメンション**ではありません**（連続的なスコアであるため）。バンド分けした表示にするには`risk`ディメンションを使うか、専用の**優先度ヒストグラム**ウィジェットを使用してください。

### フィルター

ウィジェットの`config.filters`は、**オブジェクトの一覧ビューと同じフィルター形式**を使います。これは一覧ページがURLに出力する値であり、生のRESTクエリパラメータではありません。例えば、検出事項では`{"status_any": "Active"}`、`{"severity": "Critical"}`、`{"duplicate": "false"}`、`{"date_past_days": 7}`、`{"sla_days_remaining_less_than_equal_to": 7}`のように、アセットでは`{"grade": "A,B,C"}`、`{"last_scanned_past_days": 90}`のように指定します。必要なフィルターを知る最も手早い方法は、UIの該当する一覧ページでそのフィルターを適用し、ウィジェット設定ダイアログから読み取るか、あらかじめ用意された共有テンプレートからフィルターをコピーすることです。

> **🔑 重要:** 存在しないフィルターの**キーは黙って無視されます**。スペルミスや存在しないフィルターはエラーにならず、単に適用されないだけなので、ウィジェットは意図したよりも広い範囲を表示することになります。実在するフィルターに対する無効な*値*は`400`を返します。必ずレイアウトを読み戻して[構築した内容を検証](#verify-what-you-built)してください。（フィルターは一覧ビューが使うのと同じFilterSetを通じて検証されるため、「いずれかに一致」させたい場合はリストの値を配列として渡せます。例: `{"severity": ["Critical", "High"]}`。）

> **💡 ヒント:** ほとんどのウィジェットは`finding`、`product`、`engagement`、`test`のいずれかを`model`として受け取ります。旧来の`product`（UIでは**アセット**と呼ばれます）に注意してください。**埋め込みテーブル**ウィジェットは例外で、その`model`には新しい名称である`finding`、`asset`、`engagement`、`test`、`risk_acceptance`、`organization`、`test_type`のいずれかを使用します。

## ステップ2: レイアウトを作成する

レイアウトは`/dashboards/layouts/`への`POST`で作成します。ダッシュボードの内容を保持する2つのフィールドは`widgets`と`layout`で、これらは互いに整合していなければなりません。

### ウィジェットオブジェクト

`widgets`配列の各エントリは次の形をしています。

```json
{
  "id": "11111111-1111-4111-8111-111111111111",
  "type": "count",
  "title": "Active Critical Findings",
  "refresh_interval": 0,
  "config": { "model": "finding", "filters": {"status_any": "Active", "severity": "Critical"}, "color": "danger", "icon": "fas fa-ban" }
}
```

- **`id`** — 自分で生成するUUIDです。ウィジェットをグリッド上の位置と結び付けます。
- **`type`** — ウィジェットカタログにある`type`の値です。
- **`title`** — ウィジェットに表示される見出しです（最大200文字）。
- **`refresh_interval`** — 自動更新の秒数で、`0`（オフ）、`30`、`60`、`300`、`900`のいずれかです。
- **`config`** — タイプ固有の設定です。カタログの`config_example`を出発点にして調整してください。各ウィジェットタイプはサーバー側で自身の設定を検証し、問題があれば説明付きの`400`を返します。
- **`title_styling`** *（省略可）* — `{"bold": true, "size": "md"}`の形式で、`size`は`sm`、`md`、`lg`のいずれかです。

### レイアウト（グリッド）マップ

`layout`は、各ウィジェットの`id`から12列グリッド上の位置へのマップです。

```json
{
  "11111111-1111-4111-8111-111111111111": {"x": 0, "y": 0, "w": 3, "h": 2, "min_w": 2, "min_h": 2}
}
```

- **`x`, `y`** — グリッド左上の座標です（0始まり、`x`は0〜11の範囲）。
- **`w`, `h`** — 幅（列数）と高さ（行数）です。
- **`min_w`, `min_h`** *（省略可、デフォルトは1）* および **`max_w`, `max_h`** *（省略可）* — サイズの上下限です。

> **🔑 重要:** `layout`マップと`widgets`リストは整合していなければなりません。**すべてのウィジェットに位置が必要であり、すべての位置は実在するウィジェットを参照していなければなりません。** 不整合があると`400`が返されます。以下のライフサイクルスクリプトは、この2つを一緒に構築するため、IDが常に一致します。

### レイアウトを作成する

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/layouts/" \
  -d '{
    "name": "Exec Overview (API)",
    "widgets": [
      {"id": "11111111-1111-4111-8111-111111111111", "type": "count", "title": "Active Critical Findings",
       "refresh_interval": 0, "config": {"model": "finding", "filters": {"status_any": "Active", "severity": "Critical"}, "color": "danger", "icon": "fas fa-ban"}},
      {"id": "22222222-2222-4222-8222-222222222222", "type": "graph", "title": "Findings by Severity",
       "refresh_interval": 0, "config": {"model": "finding", "filters": {"duplicate": "false"}, "group_by": "severity", "aggregation": "count", "chart_type": "pie", "time_bucket": null, "limit": null, "stacked": false}}
    ],
    "layout": {
      "11111111-1111-4111-8111-111111111111": {"x": 0, "y": 0, "w": 3, "h": 2, "min_w": 2, "min_h": 2},
      "22222222-2222-4222-8222-222222222222": {"x": 3, "y": 0, "w": 9, "h": 4, "min_w": 3, "min_h": 3}
    },
    "settings": {}
  }'
```

レスポンスには、新しい`id`を含む保存済みレイアウトがそのまま返されるほか、読み取り専用の補助フィールド（`is_default`、`is_owned`、`is_catalog`、`category`、`icon`、各種タイムスタンプ）も含まれます。

### カスタムアクション

| アクション | 呼び出し | 内容 |
|--------|------|--------------|
| デフォルト設定 | `POST /dashboards/layouts/{id}/set_default/` | このレイアウトを、ホームページ読み込み時に使われるものにします。デフォルトに設定できるのは自分が所有するレイアウトのみです。 |
| 複製 | `POST /dashboards/layouts/{id}/clone/`（任意のボディ`{"name": "..."}`） | レイアウト（自分のものまたは共有テンプレート）を、新しいウィジェットIDを付けて自分の領域にコピーします。デフォルトの名前は`"Copy of <name>"`です。 |
| 共有一覧の取得 | `GET /dashboards/layouts/shared/` | 厳選されたテンプレートとチームが公開したものを含む、すべての共有レイアウトを一覧表示します。 |
| ブートストラップ | `GET /dashboards/layouts/for_current_user/` | `{"results": [...自分のレイアウト...], "default_id": <id>}`を返します。初回呼び出し時には、常に少なくとも1つのレイアウトが返されるよう、スターターテンプレートが自動的に複製されます。 |

共有レイアウトを公開する（作成または更新時に`"is_shared": true`を指定する）には、グローバルの**Maintainer**ロールが必要です。

## ステップ3: ウィジェットデータをレンダリングする（任意）

通常、自分でデータをレンダリングする必要はありません。ウィジェットを表示する際にダッシュボードがその処理を行います。しかし、同じ`widget_data`エンドポイントは直接利用することもでき、最新の数値を引用したいスクリプトやチャットの要約などに便利です。ペイロードとしてウィジェットの`config`（またはその一部）を送信してください。

**フィルターを適用した件数**（`POST`）:

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_data/count/" \
  -d '{"model": "finding", "filters": {"status_any": "Active", "severity": "Critical"}}'
# → {"count": 42}
```

**グループ化による集計**（`POST`）、グラフの背後にあるデータです。

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_data/aggregate/" \
  -d '{"model": "finding", "filters": {}, "group_by": "severity", "aggregation": "count"}'
```

```json
{
  "labels": ["Critical", "High", "Medium", "Low", "Info"],
  "series": [{"name": "count", "data": [15, 23, 8, 12, 5]}],
  "group_by": "severity",
  "group_by_label": "Severity",
  "model": "finding",
  "model_label": "Findings",
  "aggregation": "count",
  "time_bucket": null
}
```

`widget_data`アクションの全一覧:

| アクション | メソッド | 主なペイロード / パラメータ | 戻り値 |
|--------|--------|----------------------|---------|
| `count` | POST | `model`, `filters` | `{count}` |
| `aggregate` | POST | `model`, `filters`, `group_by`, `aggregation`, `time_bucket?`, `limit?` | `{labels, series, ...}` |
| `dimensions` | GET | `?model=` | 有効なグループ化ディメンション |
| `top_records` | POST | `model`, `filters`, `metric`, `limit?`, `sort?` | `{labels, series, ...}` |
| `record_metrics` | GET | `?model=` | レコードモードで有効な指標 |
| `rate_chart` | POST | `model`, `filters`, `pass_filters`, `group_by`, `limit?`, `sort?`, `min_denominator?`, `metric_label?` | 比率／分子／分母の系列 |
| `sankey` | POST | `model?`, `filters`, `source_dim`, `target_dim` | `{nodes, links, ...}` |
| `sunburst` | POST | `model?`, `filters`, `hierarchy`（1〜2ディメンション） | `{tree, ...}` |
| `scan_coverage` | POST | `model?`, `filters`, `windows?` | ウィンドウごとの帯 |
| `risk_matrix` | POST | `filters`, `x_dim?` | EPSS × リスクのセル（検出事項限定） |
| `priority_histogram` | POST | `filters`, `bin_count?` | ヒストグラムのビン（検出事項限定） |
| `treemap` | POST | `filters`, `metric?` | 入れ子になったポートフォリオツリー |
| `heatmap` | POST | `filters`, `date_field?`, `window_days?` | 日別のカレンダーセル |
| `aging` | POST | `filters`, `boundaries?`, `date_field?`, `severity_filter?` | 積み上げ経過期間帯の系列 |
| `mttr_mttd` | POST | `filters`, `time_bucket?`, `window_days?` | MTTR/MTTDのペア系列 |
| `velocity` | POST | `filters`, `time_bucket?`, `window_days?` | 作成数と対応完了数の系列 |
| `my_work` | GET | `?buckets=`, `?limit=` | 自分の割り当て／メンション／保留中のレビュー |
| `sla_burndown` | GET | `?days_threshold=`, `?severity_filter=`, `?limit=`, `?include_overdue=` | SLA違反が近い検出事項 |
| `recent_activity` | GET | `?model=`, `?limit=` | 最近のレコードフィード |
| `saved_reports` | GET | `?limit=` | 保存済みレポートテンプレート *（Reportingが必要）* |
| `usage` | GET | — | ライセンス使用状況の内訳 *（Maintainerが必要）* |

## まとめ: 完全なライフサイクルスクリプト

以下のスクリプトは、Python 3標準ライブラリのみを使って（`requests`もサードパーティ製パッケージも使わずに）フロー全体を実行します。`DD_IMPORTER_DOJO_API_TOKEN`からトークンを読み込み、ウィジェットカタログを取得し、（`widgets`リストと`layout`マップを一緒に生成してIDを常に一致させながら）2つのウィジェットからなるレイアウトを構築し、作成し、デフォルトに設定し、読み戻して検証し、作成されたIDを`created.json`に書き込みます。

インスタンスのURLを設定して実行してください。

```bash
export DD_IMPORTER_DOJO_API_TOKEN="YOUR_API_TOKEN"
export DD_BASE_URL="https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2"
python3 build_dashboard.py
```

```python
#!/usr/bin/env python3
"""Build a DefectDojo Pro dashboard layout end-to-end using only the stdlib."""

import json
import os
import urllib.error
import urllib.request
import uuid

# --- Configuration -------------------------------------------------------
BASE_URL = os.environ.get(
    "DD_BASE_URL",
    "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2",
).rstrip("/")
TOKEN = os.environ["DD_IMPORTER_DOJO_API_TOKEN"]  # fail loudly if unset


def api_request(method, path, body=None):
    """Make an authenticated request. Returns parsed JSON."""
    url = f"{BASE_URL}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None

    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Authorization", f"Token {TOKEN}")
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

    return json.loads(payload) if payload else {}


def make_widget(widget_type, title, config, *, x, y, w, h, min_w=2, min_h=2):
    """Build a (widget, position) pair sharing a freshly generated UUID."""
    widget_id = str(uuid.uuid4())
    widget = {
        "id": widget_id,
        "type": widget_type,
        "title": title,
        "refresh_interval": 0,
        "config": config,
    }
    position = {"x": x, "y": y, "w": w, "h": h, "min_w": min_w, "min_h": min_h}
    return widget_id, widget, position


def main():
    created = {}

    # 1. Discover the catalog so we build against real widget types.
    #    (We don't strictly need the response here, but fetching it first
    #    is the recommended pattern — copy a config_example as a starting
    #    point instead of guessing the config shape.)
    catalog = api_request("GET", "/dashboards/widget_catalog/")
    known_types = {w["type"] for w in catalog["widgets"]}
    for required in ("count", "graph"):
        if required not in known_types:
            raise SystemExit(f"Widget type {required!r} not in catalog.")
    print(f"Discovered {len(known_types)} widget types.")

    # 2. Build two widgets and their grid positions together.
    widgets = []
    layout = {}

    _id, widget, pos = make_widget(
        "count",
        "Active Critical Findings",
        {
            "model": "finding",
            "filters": {"status_any": "Active", "severity": "Critical"},
            "color": "danger",
            "icon": "fas fa-ban",
        },
        x=0, y=0, w=3, h=2,
    )
    widgets.append(widget)
    layout[_id] = pos

    _id, widget, pos = make_widget(
        "graph",
        "Findings by Severity",
        {
            "model": "finding",
            "filters": {"duplicate": "false"},
            "group_by": "severity",
            "aggregation": "count",
            "chart_type": "pie",
            "time_bucket": None,
            "limit": None,
            "stacked": False,
        },
        x=3, y=0, w=9, h=4, min_w=3, min_h=3,
    )
    widgets.append(widget)
    layout[_id] = pos

    # 3. Create the layout.
    created_layout = api_request("POST", "/dashboards/layouts/", {
        "name": "Exec Overview (API)",
        "widgets": widgets,
        "layout": layout,
        "settings": {},
    })
    layout_id = created_layout["id"]
    created["layout_id"] = layout_id
    print(f"Created layout id={layout_id} with {len(created_layout['widgets'])} widgets")

    # 4. Make it the default landing dashboard.
    api_request("POST", f"/dashboards/layouts/{layout_id}/set_default/")
    print(f"Set layout id={layout_id} as the default")

    # 5. Read it back to verify widgets + positions survived intact.
    verified = api_request("GET", f"/dashboards/layouts/{layout_id}/")
    assert verified["is_default"] is True, "Layout did not become the default"
    assert len(verified["widgets"]) == len(widgets), "Widget count mismatch"
    assert set(verified["layout"]) == {w["id"] for w in verified["widgets"]}, \
        "Layout map and widgets are out of sync"
    print("Verified: default set, widgets and positions consistent")

    # 6. Record the created ID for later cleanup or reuse.
    with open("created.json", "w") as handle:
        json.dump(created, handle, indent=2)
    print("Wrote created.json")


if __name__ == "__main__":
    main()
```

## 構築した内容を検証する

無効なフィルターキーは黙って破棄されるため、検証は後付けではなく、ワークフローの一部です。

**レイアウトが意図どおりに保存されたことを確認します。** `GET`で読み戻し、`widgets`と`layout`を確認してください。

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/layouts/12/"
```

各ウィジェットについて、返された`config.filters`を送信した内容と比較してください。想定していたフィルターが欠けている場合、そのキーはそのモデルに対する有効なフィルターではなかったということです。オブジェクトの一覧ビューのフィルターと照らし合わせて再確認してください。設定した場合は`is_default`が`true`になっていること、そして`layout`内のすべてのキーがウィジェットの`id`と一致していることを確認してください。

**ウィジェットのデータを抜き取り確認します。** データエンドポイントをレンダリングし、数値が期待どおりであることを確認してください。

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_data/count/" \
  -d '{"model": "finding", "filters": {"status_any": "Active", "severity": "Critical"}}'
```

**PATCHでウィジェットを修正します。** 完全な`widgets`と`layout`を伴う`/dashboards/layouts/{id}/`への`PATCH`は、それらを置き換えます。部分的な集合ではなく、望む完全な集合を送信してください。

## 次のステップ

- [カスタムダッシュボードUI](../custom-dashboards/)で、同じレイアウトを対話的に構築・配置できます。
- [ダッシュボードのLLM連携](../custom-dashboards-llm/)を使って、LLMにダッシュボードの設計と構築を任せることもできます。
