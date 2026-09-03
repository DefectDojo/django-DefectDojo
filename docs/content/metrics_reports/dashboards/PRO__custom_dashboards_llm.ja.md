---
title: LLMでダッシュボードを構築する
description: Claudeや他のLLMを使って、API経由でDefectDojo Proのカスタムダッシュボードを設計、作成、設定する
draft: false
audience: pro
weight: 12
slug: custom-dashboards-llm
---

<span style="background-color:rgba(242, 86, 29, 0.3)">注: REST APIとLLMによるカスタムダッシュボードの自動化はDefectDojo Proの機能です。デフォルトでは無効になっており、スーパーユーザーがCloudおよびOn-Premiseの両方のインスタンスで**設定 > 機能フラグ**からカスタムダッシュボードを有効にできます。</span>

DefectDojo Proのカスタムダッシュボードは完全にREST APIによって駆動されており、レイアウト機能はAIエージェントを念頭に置いて設計されています。つまり、作業全体をLLMに任せることができます。自己完結型のプロンプトを一つ、Claude、ChatGPT、その他の高性能なモデルに貼り付けて、欲しいダッシュボードを説明するだけで、モデルがテナントのライブウィジェットカタログを調べ、レイアウトを提案し、実行可能なPythonスクリプトを生成し、レイアウトを作成、検証し、必要に応じてデフォルトとして設定します。

パターンはシンプルです。ベースURL、APIトークン、そしてダッシュボードが誰のためのものかを簡単に説明するだけです。LLMが発見、設計、作成、検証を行い、テナントに対して何かを構築する前には承認を求めて一旦停止します。

本ガイドは、LLMが操作する生のリソースとリクエストの形式を解説した[ダッシュボードAPIガイド](../custom-dashboards-api/)と対になっています。LLMが生成したものを理解したり、手動で調整したりしたい場合は、そのリファレンスを開いたままにしておいてください。

## 始める前に

1. **APIトークンを取得します。** DefectDojo ProのUIで**ユーザー設定 → API v2キー**に移動し、トークンをコピーします。次に、生成されたスクリプトがトークンを読み取れるように、チャットにトークンが表示されないよう環境変数として設定します。

```shell
export DD_IMPORTER_DOJO_API_TOKEN=<paste-token-here>
```

2. **機能が有効になっていることを確認します。** インスタンスで**設定 > 機能フラグ**からカスタムダッシュボードを有効にしておく必要があります。有効になっていないと、すべてのAPI呼び出しが`403`を返します。

3. **ダッシュボードを決めます。** LLMが何を求めているか尋ねてきます。よくある選択肢は次のとおりです。

   - **経営層向け概要（Executive Overview）** — 主要な件数、深刻度の分布、SLA遵守状況を一目で把握できます。
   - **日次トリアージ（Daily Triage）** — アクティブな重大・高の検出事項、優先度ヒストグラム、SLAバーンダウン、自分の「マイワーク」キューです。
   - **改善速度（Remediation Velocity）** — 作成数と対応完了数の推移、MTTR/MTTD、経過期間（Aging）です。
   - **スキャナーの有効性（Scanner Effectiveness）** — テストタイプ別の検出事項、ツール別の誤検知率、最近のスキャンアクティビティです。
   - **ポートフォリオの健全性（Portfolio Health）** — 組織別アセットのツリーマップ、スキャンカバレッジ、評価の高い・低いアセットです。

> **💡 ヒント:** このリストから選ぶ必要はありません。自分の本当の目的を平易な言葉でLLMに伝えれば、利用可能なウィジェットタイプとフィルターにマッピングしてくれます。

## プロンプト

以下のフェンスで囲まれたブロック全体をコピーし、Claude、ChatGPT、その他の高性能なLLMに貼り付けてください。このプロンプトは自己完結型で、モデルがテナントのURL、トークンの環境変数名、ダッシュボードの目標を尋ねたうえで、発見 → 設計 → 作成 → 検証の手順を案内します。

```text
You are helping me build customizable dashboards in DefectDojo Pro using its
REST API ("Dashboards 2.0" — layouts of widgets on a grid). Work carefully and
pause for my approval before creating anything against my tenant.

================================================================================
WHAT I WILL GIVE YOU
================================================================================
  - A base URL ending in /api/v2 (e.g. https://my-instance.cloud.defectdojo.com/api/v2)
  - The name of an environment variable holding my API token (default:
    DD_IMPORTER_DOJO_API_TOKEN). NEVER ask me to paste the token itself.
  - A description of the dashboard(s) I want and who they are for.

Authenticate every request with the header:  Authorization: Token <token>
Also send  Accept: application/json  (and Content-Type: application/json on writes).

================================================================================
DATA MODEL
================================================================================
A "layout" is one dashboard: a named set of widgets and their grid positions.
It is created/updated under /api/v2/dashboards/ with these resources:

  /api/v2/dashboards/layouts/         CRUD for layouts + actions:
        POST {id}/clone/        copy a layout (fresh widget IDs)
        POST {id}/set_default/  make a layout my home-page default
        GET  shared/            list curated + team-shared templates
        GET  for_current_user/  my layouts + my default_id (bootstrap)
  /api/v2/dashboards/widget_catalog/  GET: every widget type + a config example
  /api/v2/dashboards/widget_data/<action>/  render a widget's data on demand

A layout's two content fields MUST agree with each other:
  widgets : ordered list of widget objects (see below)
  layout  : map of  widget-id -> {x, y, w, h, min_w?, min_h?, max_w?, max_h?}
Every widget needs a position, and every position must reference a real widget,
or the create returns 400.

A widget object:
  {
    "id": "<uuid you generate>",
    "type": "<a type from the catalog>",
    "title": "<heading>",
    "refresh_interval": 0,        # one of 0, 30, 60, 300, 900 (seconds)
    "config": { ...type-specific... }
  }
Optional: "title_styling": {"bold": true, "size": "md"}  # size: sm | md | lg

The grid is 12 columns wide. x is 0..11; w is the column span; y/h are rows.

================================================================================
STEP 1 — DISCOVER (do this BEFORE designing anything; never invent values)
================================================================================
1. GET /api/v2/dashboards/widget_catalog/ . It returns {categories, widgets}.
   Each widget entry has: type, label, category, description, data_endpoints,
   and a minimal known-good config_example. USE THESE config_examples as the
   starting point for each widget's config — do not guess the config shape.
   There are 26 widget types in four categories: Numbers, Charts,
   Lists & Feeds, Static & Utility.

2. For any chart/leaderboard that groups data, fetch the valid dimensions:
     GET /api/v2/dashboards/widget_data/dimensions/?model=<finding|product|engagement|test>
   Each dimension has key, label, and kind (categorical | boolean | time |
   banded). Pass the key as the widget's group_by. A "time" dimension also
   needs a time_bucket (day|week|month|quarter|year); others do not.
   NOTE: "priority" is NOT a group-by dimension (it is a continuous score).
   Use the "risk" dimension for a banded view, or the priority_histogram widget.

3. For the Top-N widget in "records" mode, fetch valid metrics:
     GET /api/v2/dashboards/widget_data/record_metrics/?model=<product|finding|engagement|test>

================================================================================
MODELS AND FILTERS (the most error-prone area — READ CAREFULLY)
================================================================================
MODEL: most widgets take a config "model" of EXACTLY one of:
       finding | product | engagement | test
   (Note the legacy "product" — the UI calls these "Assets", and
    "engagement"/"test" are unchanged.) Some widgets are finding-only and take
    no model (risk_matrix, priority_histogram). The EMBEDDED TABLE widget is the
    exception: its model uses the newer names and a wider set:
       finding | asset | engagement | test | risk_acceptance | organization | test_type

FILTERS: a widget's config.filters use the SAME shape the object's LIST VIEW
   emits — not raw REST query params. Examples that work:
     finding:  {"status_any": "Active"}        # Active | Mitigated | Risk Accepted | ...
               {"severity": "Critical"}         # single value (or a list for any-of)
               {"duplicate": "false"}           # boolean as a string
               {"date_past_days": 7}
               {"sla_days_remaining_less_than_equal_to": 7}
     asset:    {"grade": "A,B,C"}               # passing; "D,F" = failing
               {"last_scanned_past_days": 90}
   An UNKNOWN filter key is SILENTLY IGNORED (no error) — so a typo leaves the
   widget showing a wider population than intended. An invalid VALUE for a real
   filter returns 400. Because of the silent-drop behavior, you MUST verify
   (Step 4). If unsure of a filter name, prefer the values shown in the catalog
   config_examples, or ask me to read the filter off the relevant list page.

================================================================================
STEP 2 — DESIGN, THEN GET MY APPROVAL
================================================================================
Propose, for each dashboard I asked for: a layout name, and a list of widgets
with their type, title, config, and a sensible 12-column grid arrangement
(x/y/w/h). Show me this plan and the exact JSON you intend to POST. Do NOT
create anything yet. Wait for my explicit "go".

================================================================================
STEP 3 — CREATE
================================================================================
After approval, emit a single Python 3 script using ONLY the standard library
(json, os, urllib, uuid — no requests). It must:
  - read the token from the env var,
  - generate a uuid4 per widget and build the widgets list and layout map
    together so their IDs always match,
  - POST each layout to /api/v2/dashboards/layouts/ and surface any error body,
  - optionally POST {id}/set_default/ for the one I choose as my landing page,
  - print the created layout IDs.

================================================================================
STEP 4 — VERIFY
================================================================================
For each created layout, GET /api/v2/dashboards/layouts/{id}/ and check:
  - every key in "layout" matches a widget "id" (and vice versa),
  - each widget's config.filters contains what we sent (flag any dropped keys),
  - is_default is true for the one I chose.
Report what you verified, and offer to PATCH fixes (a PATCH replaces the full
widgets + layout, so always send the complete set).

================================================================================
NOW START
================================================================================
Ask me for: (1) my base URL, (2) the token env-var name (default
DD_IMPORTER_DOJO_API_TOKEN), and (3) the dashboards I want and their audience.
Then begin at Step 1.
```

## 何が起こるか

適切に動作するモデルは、次のようになります。

1. ベースURL、トークンの環境変数名、ダッシュボードの目標を尋ねます。
2. ウィジェットカタログ（必要に応じてdimensions/record-metricsも）を`GET`し、どのウィジェットタイプを使う予定か教えてくれます。
3. 各レイアウト（名前、ウィジェット、フィルター、グリッド配置）を提案し、**承認を待ちます**。
4. 標準ライブラリのみを使ったPythonスクリプトを生成し、レイアウトを作成し、必要に応じてデフォルトを設定し、結果を検証します。
5. 検証した内容を報告し、意図どおりに保存されなかったものがあれば修正を提案します。

> **💡 ヒント:** ウィジェットが予期しない数値を表示する場合、多くの場合は暗黙的に破棄されたフィルターキーが原因です。LLMにレイアウトを読み戻させ、保存された`config.filters`を送信した内容と比較させてください。この検証手順の詳細は[APIガイド](../custom-dashboards-api/#verify-what-you-built)で解説しています。

## 次のステップ

- 生のリソース、リクエストの形式、ウィジェットデータアクションの完全なリファレンスについては、[ダッシュボードAPIガイド](../custom-dashboards-api/)を参照してください。
- [カスタムダッシュボードUI](../custom-dashboards/)で手動でダッシュボードを構築・配置できます。
