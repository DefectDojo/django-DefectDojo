---
title: 使用 LLM 构建报告
description: 通过 API 使用 Claude 或其他 LLM 设计、创建、运行并下载 DefectDojo Pro 报告
draft: false
audience: pro
weight: 22
slug: report-builder-llm
---

<span style="background-color:rgba(242, 86, 29, 0.3)">注意：通过 REST API 和 LLM 自动化报告构建器是 DefectDojo Pro 的功能，目前处于测试阶段。</span>

DefectDojo Pro 的报告构建器（主题、内容块和模板）完全由 REST API 驱动。这意味着您可以把整个任务交给 LLM 来完成：将一段自包含的提示词粘贴到 Claude、ChatGPT 或其他任何有能力的模型中，它会查询您租户的实时 OpenAPI 架构和 `field_options`，为您指定的受众提出一套主题以及可复用的内容块库和模板，生成一个可运行的 Python 脚本，然后运行报告并下载生成的文件。

这种模式很简单。您提供基础 URL、API 令牌，以及报告受众的简短说明。LLM 负责发现、设计、创建、验证、运行和下载——在对您的租户执行任何构建操作之前，会先暂停以征求您的批准。

本指南与 [报告构建器 API 指南](../report-builder-api/) 配套使用，该指南记录了 LLM 所使用的原始资源和请求格式。如果您想理解或手动调整 LLM 生成的内容，请将该指南保持在手边作为参考。

## 开始之前

1. **获取 API 令牌。** 在 DefectDojo Pro 界面中，进入 **User Settings → API v2 Key**，复制该令牌。然后将其设置为环境变量，以便生成的脚本可以读取，而令牌本身不会出现在聊天记录中：

```shell
export DD_IMPORTER_DOJO_API_TOKEN=<paste-token-here>
```

2. **确定报告受众。** LLM 会询问报告的目标受众。常见选择包括：

   - **执行摘要（Executive Summary）** — 高层次安全态势总览：一目了然地查看超期 SLA、KEV（已知被利用漏洞）和资产清单。
   - **POA&M（行动计划与里程碑）** — 列出未结的发现项及其严重程度、截止日期和建议的修复措施，并包含严重级别详情和历史/已关闭的发现项。
   - **集成资产清单工作簿** — 范围内的资产（原“产品”），包含关键性、平台、生命周期阶段、是否可从互联网访问，以及发现项数量。
   - **偏差申请（DRF）文档包** — 有效的风险接受、标记为 DR 的发现项，以及可作为新偏差申请候选的超期 SLA 项。
   - **工程发现项详情** — 每个发现项的完整说明（描述、影响、缓解措施、参考资料）。
   - **合规/审计快照** — 资产、风险接受和 KEV 信息的组合。

> **💡 Tip:** 您不必局限于此列表。用简单明了的语言告诉 LLM 您真实的报告受众，它会将其映射到可用的实体和过滤条件上。

## 提示词

复制下方整个代码块，并将其粘贴到 Claude、ChatGPT 或其他任何有能力的 LLM 中。该提示词是自包含的——模型会向您询问租户 URL、保存令牌的环境变量名称，以及报告受众，然后引导您完成发现 → 设计 → 创建 → 验证 → 运行 → 下载的全过程。

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

## 使用方法

1. **将上面的提示词粘贴** 到 Claude、ChatGPT 或其他有能力的 LLM 中。
2. **回答它的发现性问题。** 它会询问您的基础 URL、保存令牌的环境变量、报告受众、您关心的具体过滤条件（严重程度分级、SLA 截止时间、仅 KEV、特定资产或标签）、品牌样式，以及您想要的输出格式。
3. **在构建之前审查并批准所提议的设计。** 模型应返回一个共享主题、一个可复用的内容块库，以及一个或多个模板——并针对每个数据块展示 `model_choice`、`fields`、排序方式和确切的过滤条件。在您确认之前，不要让它对您的租户执行任何创建操作。
4. **让它生成并运行脚本。** 这个单一的 Python 脚本（仅使用标准库）会创建主题、内容块和模板，然后运行报告并下载生成的文件。
5. **它应在运行前后进行验证。** 预期它会通过 GET 请求逐一取回每个内容块和模板，确认过滤条件和排序已正确保存，然后向 `generated_reports` 发送 POST 请求，轮询直到状态变为 `completed`，再下载文件。

> **💡 Tip:** 如果 LLM 没有先获取您租户的实时架构（`/api/v2/oa3/schema/?format=json`）和 `field_options` 就直接开始设计内容块，请让它先完成这一步。过滤条件和字段名称因版本而异，凭记忆设计正是导致内容块中过滤条件悄悄丢失的原因。

## 故障排查

**创建的内容块中缺少您发送的过滤条件。** 过滤条件的 `field` 名称与底层实体的实际 GET 参数不匹配，因此 DefectDojo 将其丢弃了。让 LLM 获取 `/api/v2/oa3/schema/?format=json`，查看该实体 GET 接口（例如发现项接口）的 `parameters` 列表，并使用真实存在的参数名称。

**布尔类型的过滤条件未生效。** 布尔值必须以字符串 `"true"` 或 `"false"` 的形式发送，而不是真正的 JSON 布尔值。

**`outside_of_sla` 没有起到过滤作用。** 该过滤条件需要以字符串形式提供的数值——应使用 `"1"`，而不是 `"true"`。

**在一个内容块中设置多个严重程度不起作用。** 单个内容块只会保留第一个严重程度值。请改为每个严重程度使用一个单独的内容块。

**模板中的内容块顺序错误或缺失。** 请确认 LLM 发送 POST 请求时使用的是 `template_blocks_write`（可写字段），而不是 `template_blocks`（只读字段）。每个条目都必须包含 `order` 字段。

**报告运行卡住或失败。** 持续轮询 `GET /api/v2/generated_reports/{id}/`——状态会从 `pending` 变为 `processing`，再变为 `completed`。如果状态变为 `failed`，请先查看 `error_message` 字段了解原因，然后再重试。

> **⚠️** 下载接口（`/api/v2/generated_reports/{id}/download/`）在运行状态达到 `completed` 之前会返回 404。请务必轮询至完成状态后再下载。

## 后续步骤

- [报告构建器（界面）](../report-builder/) — 在 DefectDojo Pro 界面中以交互方式设计和运行报告。
- [报告构建器 API](../report-builder-api/) — LLM 所使用的原始 REST 资源和请求格式，供手动调整或深度自动化使用。
