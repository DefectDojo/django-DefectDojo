---
title: LLMを使ったレポート作成
description: Claudeやその他のLLMを使用して、APIを通じてDefectDojo Proレポートの設計、作成、実行、ダウンロードを行う
draft: false
audience: pro
weight: 22
slug: report-builder-llm
---

<span style="background-color:rgba(242, 86, 29, 0.3)">注: REST APIとLLMを使用したレポートビルダーの自動化は、DefectDojo Proの機能であり、現在ベータ版です。</span>

DefectDojo Proのレポートビルダー(テーマ、ブロック、テンプレート)は、REST APIによって完全に駆動されます。つまり、作業全体をLLMに任せることができます。自己完結型のプロンプトを1つ、Claude、ChatGPT、その他の高性能なモデルに貼り付けるだけで、テナントのライブOpenAPIスキーマと `field_options` を調査し、指定した対象者向けのテーマと再利用可能なブロックライブラリおよびテンプレートを提案し、実行可能なPythonスクリプトを生成した上で、レポートを実行して完成したファイルをダウンロードしてくれます。

パターンはシンプルです。ベースURL、APIトークン、そしてレポートの対象者についての簡単な説明を用意するだけです。LLMが調査、設計、作成、検証、実行、ダウンロードを行いますが、テナントに対して何かを構築する前には、必ずあなたの承認を待って一時停止します。

本ガイドは[レポートビルダーAPIガイド](../report-builder-api/)と対になっており、LLMが操作する生のリソースとリクエスト形式について説明しています。LLMが生成した内容を理解したり、手動で調整したりしたい場合は、このリファレンスを開いておいてください。

## 開始する前に

1. **APIトークンを取得する。** DefectDojo Pro UIで、**ユーザー設定 → API v2キー** に移動し、トークンをコピーします。次に、生成されたスクリプトがチャットにトークンを表示させることなく読み取れるように、環境変数として設定します。

```shell
export DD_IMPORTER_DOJO_API_TOKEN=<paste-token-here>
```

2. **対象者を決める。** LLMはレポートの対象者を尋ねます。一般的な選択肢は次のとおりです。

   - **Executive Summary(エグゼクティブサマリー)** — 全体的なセキュリティ態勢の概要。SLA超過、KEV、資産インベントリを一目で確認できます。

   - **POA&M(Plan of Action & Milestones)** — 深刻度、期限、推奨される対策を含む未対応の検出事項に加え、重大な詳細情報や過去の/クローズ済みの検出事項。

   - **Integrated Inventory Workbook(統合インベントリワークブック)** — 対象範囲内の資産(旧称:製品)について、重要度、プラットフォーム、ライフサイクル、インターネットからのアクセス可否、検出事項数を記載。

   - **Deviation Request (DRF) Package(逸脱申請パッケージ)** — 有効なリスク受容済み、DRタグ付きの検出事項、および新規逸脱申請の候補となるSLA超過の検出事項。

   - **Engineering Findings Detail(エンジニアリング向け検出事項詳細)** — 検出事項ごとの詳細な記述(説明、影響、緩和策、参考情報)。

   - **Compliance / Audit Snapshot(コンプライアンス/監査スナップショット)** — 資産、リスク受容済み、KEVを組み合わせたもの。

> **💡 ヒント:** このリストから選ぶ必要はありません。実際の対象者を平易な言葉でLLMに伝えれば、利用可能なエンティティとフィルターにマッピングしてくれます。

## プロンプト

以下のフェンスで囲まれたブロック全体をコピーし、Claude、ChatGPT、またはその他の高性能なLLMに貼り付けてください。このプロンプトは自己完結型で、モデルがテナントURL、トークンの環境変数名、レポートの対象者を尋ねた上で、調査 → 設計 → 作成 → 検証 → 実行 → ダウンロードの流れを案内してくれます。

```text
You are helping me build, run, and download custom reports in DefectDojo Pro
using its REST API and "Report Generator" (Themes / Blocks / Templates /
Generated Reports).

================================================================================
DATA MODEL
================================================================================

DefectDojo Pro custom reports use these related REST resources (all under
/api/v2/):

  report_themes      visual style
  report_blocks      reusable content units (filters live here)
  report_templates   ordered blocks + a theme
  generated_reports  run a template and download the resulting PDF/HTML

A Template references Blocks by ID and a Theme by ID. A Block carries its own
filters, so reusing a Block reuses its filters identically everywhere. A
Generated Report runs a Template and produces a downloadable file.

================================================================================
THEMES
================================================================================

A Theme controls the visual style applied to a template. Its fields are:

  name              display name for the theme
  primary_color     7-char hex (default #1e3a5f)
  secondary_color   7-char hex (default #4a90a4)
  accent_color      7-char hex (default #e67e22)
  text_color        7-char hex (default #333333)
  background_color  7-char hex (default #ffffff)
  footer_text       text shown in the page footer
  show_page_numbers boolean -- whether to print page numbers
  header_image      optional image for the page header
  footer_image      optional image for the page footer

All color values are 7-character hex strings (e.g. "#1e3a5f").

================================================================================
BLOCK TYPES
================================================================================

A Block's `block_type` is one of: stock | tabular | detail
  - stock    : non-data content (cover_page, table_of_contents, page_break,
               image, text_block). Config goes in `stock_configuration`.
  - tabular  : a table of records from a DefectDojo entity. Config in
               `tabular_configuration`. Required: model_choice, fields[], ordering.
  - detail   : a per-record detail layout (good for long-text fields like
               description, impact, mitigation). Config in
               `detail_configuration`. Same required keys as tabular.

(A `chart` block type is reserved but not yet exposed via the API.)

`model_choice` is locked to one of EXACTLY these seven entities (this is an
enum in the OpenAPI schema -- do not invent others):

    organization | asset | engagement | test | finding | test_type | risk_acceptance

NOTE: Even if the tenant has REST endpoints like /api/v2/location/,
/api/v2/location_findings/, or /api/v2/location_products/, those are NOT
selectable as `model_choice`. Any "location" scoping must flow through asset
(formerly Product), tag, or organization (formerly Product Type) filters on
the supported entities.

================================================================================
FIELDS (columns) -- discover, never invent
================================================================================

For each entity above, the list of valid `fields` (column paths) plus which
paths are allowed for `tabular` vs `detail` blocks is exposed at:

    GET /api/v2/report_blocks/field_options/

You MUST fetch this before designing any block. Use only the `path` values it
returns. Some fields are `detail`-only (description, mitigation, impact,
references, etc.) because they hold long-form / markdown content.

================================================================================
FILTERS -- this is the most error-prone area; READ CAREFULLY
================================================================================

Each tabular/detail block accepts:

    "filter_entries": [
        {"field": "<filter_name>", "value": "<string_value>"},
        ...
    ]

The OpenAPI schema does NOT enumerate valid filter names. The valid vocabulary
is the GET query-parameter vocabulary of the underlying REST endpoint for that
entity. To discover the real filter names for an entity:

    finding         -> GET /api/v2/findings/         (look at `parameters`)
    asset           -> GET /api/v2/assets/          (formerly Products)
    engagement      -> GET /api/v2/engagements/
    test            -> GET /api/v2/tests/
    test_type       -> GET /api/v2/test_types/
    organization    -> GET /api/v2/organizations/   (formerly Product Types)
    risk_acceptance -> GET /api/v2/risk_acceptance/

The fastest way is to load the full OpenAPI schema once:

    GET /api/v2/oa3/schema/?format=json

then, for each entity, read
    schema['paths'][<endpoint>]['get']['parameters']
and use those `name` values as your filter `field` keys.

DO NOT invent UI-style filter names (older docs sometimes mention
`status_any`, `priority_greater_than`, or comma-separated multi-value strings
like "Critical,High"). The DD Pro server SILENTLY DROPS or rewrites any
filter_entry whose `field` does not match a real GET-parameter name on the
underlying endpoint. Examples of names that DO work, from a live 2.58.x
tenant, on findings:

    {"field": "active",          "value": "true"}     boolean
    {"field": "verified",        "value": "true"}     boolean
    {"field": "is_mitigated",    "value": "true"}     boolean
    {"field": "risk_accepted",   "value": "true"}     boolean
    {"field": "duplicate",       "value": "false"}    boolean
    {"field": "false_p",         "value": "false"}    boolean
    {"field": "out_of_scope",    "value": "false"}    boolean
    {"field": "severity",        "value": "Critical"} single value (NOT comma-separated)
    {"field": "known_exploited", "value": "true"}     boolean
    {"field": "ransomware_used", "value": "true"}     boolean
    {"field": "outside_of_sla",  "value": "1"}        NUMERIC (not boolean string)
    {"field": "priority_min",    "value": "800"}      use _min / _max, not _greater_than
    {"field": "priority_max",    "value": "1000"}
    {"field": "tag",             "value": "DR"}       single tag
    {"field": "tags",            "value": "kev,pci"}  multiple tags (any-of)
    {"field": "tags__and",       "value": "kev,pci"}  multiple tags (all-of)
    {"field": "test__engagement__product",         "value": "<product_id>"}
    {"field": "test__engagement__product__prod_type","value": "<prod_type_id>"}
    {"field": "cve",             "value": "CVE-2024-12345"}
    {"field": "cwe",             "value": "79"}
    {"field": "planned_remediation_date_before", "value": "2025-12-31"}
    {"field": "date_before",     "value": "2025-12-31"}
    {"field": "date_after",      "value": "2025-01-01"}

Asset filters (examples confirmed on live tenant):

    {"field": "business_criticality", "value": "very_high"}
    {"field": "internet_accessible",  "value": "true"}
    {"field": "lifecycle",            "value": "production"}
    {"field": "platform",             "value": "web"}
    {"field": "tag",                  "value": "pci"}

Risk-acceptance filters (note: no `tag` filter exists here -- filter by
`decision`, `owner`, or `expiration_date` instead, or push the DR-marking
tag onto the underlying findings):

    {"field": "decision",         "value": "Accept (Transfer)"}
    {"field": "owner",            "value": "<user_id>"}
    {"field": "expiration_date_before", "value": "2025-12-31"}

Operational rules for filter_entries:

  - Single-value strings only. "Critical,High" in one severity entry will NOT
    keep both -- DefectDojo will store only "Critical". To cover multiple
    severities, create separate blocks (one per severity) or compose multiple
    filter rows where the underlying endpoint supports it (e.g. tags__and).
  - Booleans go as the LITERAL string "true" or "false".
  - PATCHing filter_entries REPLACES the whole list. Always send the full
    desired set; never assume merge semantics.
  - After POSTing a block, GET it back and compare the returned filter_entries
    against what you sent. If any entry is missing, the field name was rejected
    -- look it up in `parameters` on the corresponding REST endpoint.

================================================================================
TEMPLATES
================================================================================

A Template ties blocks together in order and binds them to a theme:

    POST /api/v2/report_templates/
    {
        "name":        "<name>",
        "description": "<short description>",
        "theme_id":    <theme_id>,
        "template_blocks_write": [
            {"order": 0, "block_id": <block_id>},
            {"order": 1, "block_id": <block_id>},
            ...
        ]
    }

The same `block_id` can appear multiple times (e.g. a "page break" block
reused several times in the same template).

================================================================================
GENERATED REPORTS -- run a template, then download the file
================================================================================

A Generated Report runs a Template and produces a downloadable file.

1. Kick off a run:

    POST /api/v2/generated_reports/
    {
        "template_id": <template_id>,
        "file_format": "pdf"      // or "html"
    }

   This returns a generated_reports record with an `id` and a `status`.

2. Poll until it finishes:

    GET /api/v2/generated_reports/{id}/

   `status` moves through: pending -> processing -> completed (or failed).
   Poll on an interval until it reaches "completed". If it reaches "failed",
   read `error_message` for the reason and stop.

3. Download the file once completed:

    GET /api/v2/generated_reports/{id}/download/

   This returns the binary PDF/HTML body. It returns 404 until status is
   "completed", so only call it after polling confirms completion. Save the
   response body to a file with the matching extension.

================================================================================
AUTH
================================================================================

Every request needs:

    Authorization: Token <my-api-token>
    Accept:        application/json
    Content-Type:  application/json   (on POST/PATCH)

Get the token from User Settings -> API v2 Key in the DefectDojo Pro UI.

================================================================================
WHAT I WANT YOU TO DO
================================================================================

1. Ask me for:
   - my DefectDojo Pro base URL (e.g. https://<tenant>.cloud.defectdojo.com/api/v2)
   - the env var name that holds my API token (default: DD_IMPORTER_DOJO_API_TOKEN)
   - the audiences/reports I want (e.g. Executive Summary, POA&M,
     Inventory Workbook, Deviation Request package, Engineering Detail,
     Compliance/Audit Snapshot)
   - any specific filters I care about (severity tiers, SLA cutoffs, KEV-only,
     specific assets, tags, etc.)
   - branding for the theme (primary/secondary/accent colors, footer text,
     whether to show page numbers)
   - which output format I want for the run: "pdf" or "html"

2. Discover the live vocabulary BEFORE designing anything:
   - GET /api/v2/oa3/schema/?format=json    and save locally
   - GET /api/v2/report_blocks/field_options/   and save locally
   - For each entity I want to report on, extract the GET parameters from the
     schema and show me the candidate filter names so we agree on vocabulary.

3. Propose a design back to me consisting of:
   - one shared theme (with the branding from step 1)
   - a reusable Block library (cover page, page breaks, intro text blocks,
     and the data tables/details I need)
   - 1+ Templates that compose those blocks for the audiences I named
   For every data block, show me: model_choice, fields[], ordering, and the
   exact filter_entries list. Wait for my approval.

4. Once I approve, generate a SINGLE Python script (stdlib only, urllib --
   no extra dependencies needed) that:
   - reads the token from the env var I named
   - POSTs the theme, then the blocks, then the templates (in that order,
     because templates reference block IDs and a theme ID)
   - prints each returned ID as it goes
   - dumps everything to a created.json file for verification
   - THEN runs and downloads the report (see steps 6-8 below) as part of the
     same script
   Show me the full script before running it.

5. After creating, VERIFY:
   - GET each created block back and confirm filter_entries persisted
     EXACTLY as POSTed. If any entry is missing, that field name was rejected
     by DD -- look it up in `parameters` on the relevant REST endpoint and
     PATCH the block with the corrected vocabulary.
   - GET each template back and confirm the block_id list and order, plus
     theme_id binding, are correct.

6. RUN the report:
   - POST /api/v2/generated_reports/ with
     { "template_id": <template_id>, "file_format": "pdf" }  (or "html")
   - capture the returned generated report `id`.

7. POLL until done:
   - GET /api/v2/generated_reports/{id}/ on a short interval.
   - statuses progress: pending -> processing -> completed/failed.
   - stop polling when status is "completed".
   - if status is "failed", read and print `error_message`, then stop.

8. DOWNLOAD the file:
   - once status is "completed", GET /api/v2/generated_reports/{id}/download/
     (it 404s until completed) and save the response body to a file with the
     correct extension (.pdf or .html).
   - print the saved file path.

9. If I later want to tune a filter, swap a block, or change colors:
   - PATCH the existing resource (do not recreate).
   - When PATCHing filter_entries, send the FULL desired list -- it replaces,
     not merges.
   - Re-run steps 6-8 to regenerate the file.

================================================================================
HARD CONSTRAINTS
================================================================================

- Do NOT invent field paths or filter names. If unsure, GET field_options
  (for column paths) or the entity's GET parameters (for filter names) and
  use only what's there.
- Do NOT use "Critical,High" or other comma-separated values inside a single
  severity/status filter_entry value -- DD will keep only the first match.
  Use one block per value, or use multi-value filters that DD's underlying
  endpoint explicitly supports (e.g. `tags`, `tags__and`).
- Do NOT use the older UI-style filter names like `status_any`,
  `priority_greater_than`, `mitigated_within_sla`, or `severity__in`. They
  are silently dropped.
- Do NOT call the download endpoint before status is "completed" -- it 404s.
- Show me each batch of commands or the full script before running it.
- Stop and ask if anything in the schema is ambiguous rather than guessing.

Start by asking me for the base URL, the env var name holding the token, my
audience goals, theme branding, and my preferred output format.
```

## 使い方

1. **プロンプトを貼り付ける。** 上記のプロンプトをClaude、ChatGPT、またはその他の高性能なLLMに貼り付けます。

2. **調査のための質問に答える。** ベースURL、トークンを保持する環境変数、対象者、気になる特定のフィルター(深刻度の階層、SLA期限、KEVのみ、特定の資産やタグなど)、ブランディング、希望する出力形式について尋ねられます。

3. **提案された設計を確認し、構築前に承認する。** モデルは、共有テーマ1つ、再利用可能なブロックライブラリ、1つ以上のテンプレートを提示し、各データブロックについて `model_choice`、`fields`、並び順、正確なフィルターエントリを示すはずです。承認するまでは、テナントに対して何も作成させないでください。

4. **スクリプトを生成・実行させる。** 単一のPythonスクリプト(標準ライブラリのみ使用)がテーマ、ブロック、テンプレートを作成し、レポートを実行して完成したファイルをダウンロードします。

5. **実行の前後で検証を行う。** 各ブロックとテンプレートをGETで取得し直して、フィルターと並び順が正しく保存されていることを確認した上で、`generated_reports` にPOSTし、ステータスが `completed` になるまでポーリングし、ファイルをダウンロードするはずです。

> **💡 ヒント:** LLMがテナントのライブスキーマ(`/api/v2/oa3/schema/?format=json`)や `field_options` を取得せずに、いきなりブロックの設計に入ろうとした場合は、押し戻してください。フィルター名やフィールド名はバージョンによって異なり、記憶だけを頼りに設計すると、ブロックのフィルターが気づかないうちに欠落する原因になります。

## トラブルシューティング

**作成したブロックで、送信したはずのフィルターが欠落している。** フィルターの `field` 名が、対象エンティティの実際のGETパラメータと一致していなかったため、DefectDojoによって破棄されました。LLMに `/api/v2/oa3/schema/?format=json` を取得させ、そのエンティティのGETエンドポイント(例:findingsエンドポイント)の `parameters` リストを確認させた上で、実在するパラメータ名を使用してください。

**真偽値フィルターが反映されない。** 真偽値は、実際のJSONブール値ではなく、文字列 `"true"` または `"false"` として送信する必要があります。

**`outside_of_sla` がフィルタリングされない。** このフィルターは数値を文字列として受け取ります。`"true"` ではなく `"1"` を使用してください。

**1つのブロックに複数の深刻度を指定しても機能しない。** 1つのブロックには最初の深刻度しか保持されません。代わりに深刻度ごとにブロックを分けてください。

**テンプレートのブロックが誤った順序で返される、または欠落している。** LLMが読み取り専用の `template_blocks` ではなく、書き込み専用フィールドの `template_blocks_write` をPOSTしていることを確認してください。`order` フィールドはすべてのエントリで必須です。

**レポートの実行が止まった、または失敗した。** `GET /api/v2/generated_reports/{id}/` のポーリングを続けてください。ステータスは `pending` → `processing` → `completed` の順に進みます。ステータスが `failed` になった場合は、再試行する前に `error_message` フィールドで原因を確認してください。

> **⚠️** ダウンロードエンドポイント(`/api/v2/generated_reports/{id}/download/`)は、実行が `completed` に達するまで404を返します。ダウンロードする前に、必ず完了までポーリングしてください。

## 次のステップ

- [レポートビルダー(UI)](../report-builder/) — DefectDojo Proのインターフェースで、対話的にレポートを設計・実行します。

- [レポートビルダーAPI](../report-builder-api/) — LLMが操作する生のRESTリソースとリクエスト形式。手動での調整やより高度な自動化に利用できます。
