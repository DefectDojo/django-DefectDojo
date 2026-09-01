---
title: 使用 LLM 构建仪表板
description: 使用 Claude 或其他 LLM，通过 API 设计、创建和配置 DefectDojo Pro 可自定义仪表板
draft: false
audience: pro
weight: 12
slug: custom-dashboards-llm
---

<span style="background-color:rgba(242, 86, 29, 0.3)">注意：通过 REST API 与 LLM 自动化可自定义仪表板是 DefectDojo Pro 功能。该功能默认处于关闭状态——超级用户可以在云端和本地部署实例上通过 **设置 > 功能开关** 启用可自定义仪表板。</span>

DefectDojo Pro 的可自定义仪表板完全由 REST API 驱动——布局接口在设计时就充分考虑了 AI 智能体的使用场景。这意味着您可以将整个任务交给 LLM 来完成：将一段自包含的提示词粘贴给 Claude、ChatGPT 或其他任何有能力的模型，描述您想要的仪表板，它就会查询您租户的实时小组件目录、提出布局方案、生成可运行的 Python 脚本、创建布局、进行验证，并可选择将其设为默认布局。

这一模式非常简单。您提供基础 URL、API 令牌，以及一段关于仪表板使用对象的简短描述。LLM 负责完成发现、设计、创建和验证工作——在对您的租户进行任何实际构建之前，会先暂停等待您的批准。

本指南与[仪表板 API 指南](../custom-dashboards-api/)配套使用，后者记录了 LLM 所使用的原始资源和请求结构。如果您想理解或手动调整 LLM 生成的内容，请保持打开该参考文档。

## 开始之前

1. **获取 API 令牌。** 在 DefectDojo Pro 界面中，进入 **用户设置 → API v2 密钥**，复制该令牌。然后将其设置为环境变量，这样生成的脚本就能读取它，而令牌本身永远不会出现在聊天记录中：

```shell
export DD_IMPORTER_DOJO_API_TOKEN=<paste-token-here>
```

2. **确认功能已启用。** 必须在您的实例上通过 **设置 > 功能开关** 启用可自定义仪表板——否则每次 API 调用都会返回 `403`。

3. **确定您需要的仪表板。** LLM 会询问您的需求。常见的选择包括：

   - **高管概览** —— 一览关键指标计数、严重程度分布和 SLA 合规情况。
   - **每日分诊** —— 活动的严重/高危发现项、优先级直方图、SLA 倒计时，以及您的“我的工作”队列。
   - **修复速度** —— 新建与已关闭对比速度、MTTR/MTTD 以及账龄分布。
   - **扫描器效能** —— 按测试类型划分的发现项、按工具划分的误报率，以及近期扫描活动。
   - **组合健康度** —— 按组织划分的资产树状图、扫描覆盖率，以及评分最高/最低的资产。

> **💡 提示：** 您不必局限于此列表中的选项。用简单明了的语言告诉 LLM 您真正的目标，它会将这些目标映射到可用的小组件类型和筛选条件上。

## 提示词

复制下面整个代码块并粘贴给 Claude、ChatGPT 或其他任何有能力的 LLM。该提示词是自包含的——模型会向您询问租户 URL、令牌环境变量名称以及仪表板目标，然后带您完成 发现 → 设计 → 创建 → 验证 的流程。

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

## 预期效果

一个行为得当的模型会：

1. 询问您的基础 URL、令牌环境变量以及仪表板目标。
2. `GET` 小组件目录（以及按需获取维度/记录指标），并告诉您它计划使用哪些小组件类型。
3. 提出每个布局方案——名称、小组件、筛选条件和网格排列——并**等待您的批准**。
4. 生成一个仅使用标准库的 Python 脚本，用于创建布局、可选地设置默认布局，并验证结果。
5. 报告它验证过的内容，并提出修复任何未按预期保存内容的方案。

> **💡 提示：** 如果某个小组件渲染出的数字与预期不符，通常是因为某个筛选键被静默丢弃了。让 LLM 将布局读取回来，并将保存的 `config.filters` 与它发送的内容进行比对——[API 指南](../custom-dashboards-api/#verify-what-you-built)详细介绍了这一验证步骤。

## 后续步骤

- 有关原始资源、请求结构以及完整的小组件数据操作参考，请参见[仪表板 API 指南](../custom-dashboards-api/)。
- 在[可自定义仪表板界面](../custom-dashboards/)中手动构建和排列仪表板。
