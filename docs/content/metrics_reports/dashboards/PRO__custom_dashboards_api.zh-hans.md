---
title: 通过 API 自动化仪表板
description: 通过 DefectDojo Pro REST API 发现小组件目录、创建和更新仪表板布局，并渲染小组件数据
draft: false
audience: pro
weight: 11
slug: custom-dashboards-api
---

<span style="background-color:rgba(242, 86, 29, 0.3)">注意：可自定义仪表板 REST API（布局、小组件目录和小组件数据）是 DefectDojo Pro 功能。该功能默认处于关闭状态——超级用户可以在云端和本地部署实例上通过 **设置 > 功能开关** 启用可自定义仪表板。</span>

可自定义仪表板 REST API 让您完全通过代码构建与在 [仪表板界面](../custom-dashboards/) 中手动组装相同的仪表板。您可以发现小组件目录、创建和更新布局、设置默认布局、与团队共享布局，甚至按需渲染小组件的数据，而无需重新实现 DefectDojo 的筛选逻辑。布局接口的设计初衷是作为 AI 智能体构建仪表板的主要入口，因此请求结构特意做到了可自省。

本指南将引导您完成完整的生命周期：进行身份验证、发现小组件词汇表、创建布局，然后验证并渲染它。

## 身份验证

每个请求都通过在 `Authorization` 标头中发送个人 API 令牌进行身份验证，并使用 `Token` 前缀（而不是 `Bearer`）。

从 DefectDojo Pro 界面的 **用户设置 → API v2 密钥** 下获取您的令牌。将其存储在环境变量中，确保它不会出现在 shell 历史记录或已提交的脚本中：

```bash
export DD_IMPORTER_DOJO_API_TOKEN="YOUR_API_TOKEN"
```

所有调用的基础 URL 是您的实例地址加上 `/api/v2`：

```
https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2
```

必需的标头：

| 标头 | 值 | 使用时机 |
|--------|-------|------|
| `Authorization` | `Token YOUR_API_TOKEN` | 每个请求 |
| `Accept` | `application/json` | 每个请求 |
| `Content-Type` | `application/json` | 带 JSON 请求体的 `POST` / `PATCH` 请求 |

一个最简单的已认证请求如下所示：

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_catalog/"
```

> **🔑 重要提示：** 整个仪表板 API 都依赖于可自定义仪表板功能。在该功能启用之前，每个端点都会返回 `403 Dashboards 2.0 is not enabled.` —— 参见[启用可自定义仪表板](../custom-dashboards/#enabling-customizable-dashboards)。

> **⚠️ 安全提示：** 您的 API 令牌拥有对您 DefectDojo 数据的完全访问权限。切勿将其粘贴到聊天记录、屏幕截图、工单或已提交的文件中。请从环境变量中读取它，一旦泄露就立即轮换，并尽可能将令牌的权限范围限定在服务账户内。

## 仪表板 API 概览

仪表板 API 由三个资源组构成，均位于 `/api/v2/dashboards/` 之下。

| 资源 | 路径 | 说明 | 操作 |
|----------|------|------------|------------|
| 布局 | `/dashboards/layouts/` | 您保存的仪表板（以及团队共享的模板） | `GET` 列表、`POST` 创建、`GET {id}/`、`PATCH {id}/`、`DELETE {id}/`，以及 `{id}/clone/`、`{id}/set_default/`、`shared/`、`for_current_user/` |
| 小组件目录 | `/dashboards/widget_catalog/` | 小组件类型菜单，附带每种类型的配置示例 | `GET`（只读） |
| 小组件数据 | `/dashboards/widget_data/<action>/` | 按需渲染某个小组件的数据 | 21 个按小组件划分的操作 |

这些端点接受 Token、Session 或 Basic 身份验证。所有逐行授权和数据范围限定都遵循 DefectDojo 标准的基于角色的访问控制——共享布局绝不会扩大查看者原本可见的数据范围。

> **💡 提示：** Vue 界面调用的是这些端点在 `/api/vue/dashboard_v2/` 下的内部镜像版本。进行自动化时，请始终使用本文档中记录的稳定、面向客户的 `/api/v2/dashboards/` 路径。

## 步骤 1：发现词汇表

如果凭猜测来配置小组件，有三处很容易出错：**小组件类型**、其**分组维度**（用于图表）以及**筛选条件**。API 为每一项都提供了权威数据来源。请先获取这些信息，然后再根据服务器实际接受的内容进行构建。

### 小组件目录

`GET /dashboards/widget_catalog/` 会返回每种小组件类型、它所属的类别、其渲染所依赖的数据端点，以及——最有用的是——一个可以直接复制作为起点的、已知可用的最小化 `config_example`：

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_catalog/"
```

响应的结构如下所示（已截断）：

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

将小组件目录中的 `type` 用作小组件的 `type`，并将其 `config_example` 用作小组件 `config` 的起点。该目录列出了四个类别下共 26 种小组件类型。

### 分组维度与记录指标

图表和排行榜类小组件将可分组或排序的字段限制在一份精选的允许列表内。请针对每个模型分别查询这些字段，而不要凭猜测：

```bash
# Valid group_by dimensions for the Graph / Sankey / Sunburst / Top-N (aggregate) widgets:
curl -s -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_data/dimensions/?model=finding"

# Valid metrics for the Top-N widget in "records" mode:
curl -s -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_data/record_metrics/?model=product"
```

`dimensions/` 会返回每个维度的 `key`（作为 `group_by` 传递的值）、便于阅读的 `label`，以及 `kind`：

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

`kind` 很重要：`time` 类型的维度（如 `date`）要求您同时发送 `time_bucket`（`day`/`week`/`month`/`quarter`/`year`）；`categorical` 或 `banded` 类型的维度则不需要。`priority` 字段特意**不**作为分组维度提供（因为它是一个连续型分值）——如需分段视图，请使用 `risk` 维度，或使用专门的**优先级直方图**小组件。

### 筛选条件

小组件的 `config.filters` 使用**与该对象列表视图相同的筛选结构**——也就是列表页面写入其 URL 的那些值，而不是原始的 REST 查询参数。例如，对于发现项：`{"status_any": "Active"}`、`{"severity": "Critical"}`、`{"duplicate": "false"}`、`{"date_past_days": 7}`、`{"sla_days_remaining_less_than_equal_to": 7}`；对于资产：`{"grade": "A,B,C"}`、`{"last_scanned_past_days": 90}`。找到所需正确筛选条件最快的方法，是先在界面中相应的列表页面上应用该筛选，然后从小组件配置对话框中读取回来，或者直接从预置的共享模板中复制筛选条件。

> **🔑 重要提示：** 未知的筛选**键会被静默忽略**——拼写错误或不存在的筛选条件不会引发报错，只是不会生效，这会导致小组件显示的数据范围比您预期的更宽泛。真实筛选条件的无效*值*会返回 `400`。请始终通过读取布局[验证您构建的内容](#verify-what-you-built)。（筛选条件通过与列表视图相同的 FilterSet 进行校验，因此列表类的值可以以数组形式传递，用于“任一匹配”：`{"severity": ["Critical", "High"]}`。）

> **💡 提示：** 大多数小组件的 `model` 取值为 `finding`、`product`、`engagement` 或 `test`——请注意这里的 `product` 是旧称（界面中称之为**资产**）。**嵌入式表格**小组件是例外：它的 `model` 使用较新的名称 `finding`、`asset`、`engagement`、`test`、`risk_acceptance`、`organization` 或 `test_type`。

## 步骤 2：创建布局

创建布局的方式是向 `/dashboards/layouts/` 发送 `POST` 请求。承载仪表板内容的两个字段是 `widgets` 和 `layout`，二者必须保持一致。

### 小组件对象

`widgets` 数组中的每个条目都具有以下结构：

```json
{
  "id": "11111111-1111-4111-8111-111111111111",
  "type": "count",
  "title": "Active Critical Findings",
  "refresh_interval": 0,
  "config": { "model": "finding", "filters": {"status_any": "Active", "severity": "Critical"}, "color": "danger", "icon": "fas fa-ban" }
}
```

- **`id`** —— 您生成的 UUID。它将小组件与其网格位置关联起来。
- **`type`** —— 来自小组件目录的 `type` 值。
- **`title`** —— 小组件上显示的标题（最多 200 个字符）。
- **`refresh_interval`** —— 自动刷新间隔（秒）；取值为 `0`（关闭）、`30`、`60`、`300` 或 `900` 之一。
- **`config`** —— 特定类型的配置。请以目录中的 `config_example` 为起点进行调整。每种小组件类型都会在服务器端校验自己的配置，如有问题会返回描述性的 `400`。
- **`title_styling`** *(可选)* —— `{"bold": true, "size": "md"}`，其中 `size` 为 `sm`、`md` 或 `lg`。

### 布局（网格）映射

`layout` 是一个映射，将每个小组件的 `id` 映射到其在 12 列网格中的位置：

```json
{
  "11111111-1111-4111-8111-111111111111": {"x": 0, "y": 0, "w": 3, "h": 2, "min_w": 2, "min_h": 2}
}
```

- **`x`、`y`** —— 左上角网格坐标（从 0 开始计数；`x` 的取值范围为 0–11）。
- **`w`、`h`** —— 宽度（以列数计）和高度（以行数计）。
- **`min_w`、`min_h`** *(可选，默认值为 1)* 以及 **`max_w`、`max_h`** *(可选)* —— 尺寸边界。

> **🔑 重要提示：** `layout` 映射与 `widgets` 列表必须保持一致：**每个小组件都需要一个位置，且每个位置都必须引用一个实际存在的小组件。** 不一致会返回 `400`。下面的生命周期脚本会将两者一起构建，从而确保它们的 ID 始终对应。

### 创建布局

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

响应会回显已保存的布局，包括其新的 `id`，以及一些只读的辅助字段（`is_default`、`is_owned`、`is_catalog`、`category`、`icon` 和时间戳）。

### 自定义操作

| 操作 | 调用 | 作用 |
|--------|------|--------------|
| 设为默认 | `POST /dashboards/layouts/{id}/set_default/` | 使该布局成为您主页加载的布局。您只能将自己拥有的布局设为默认。 |
| 克隆 | `POST /dashboards/layouts/{id}/clone/`（可选请求体 `{"name": "..."}`） | 将一个布局（您自己的或某个共享模板）复制到您的空间中，并生成全新的小组件 ID。默认名称为 `"Copy of <name>"`。 |
| 列出共享项 | `GET /dashboards/layouts/shared/` | 列出所有共享布局——包括精选模板和团队发布的布局。 |
| 引导获取 | `GET /dashboards/layouts/for_current_user/` | 返回 `{"results": [...your layouts...], "default_id": <id>}`。首次调用时，它会自动克隆起始模板，确保您始终能获得至少一个布局。 |

发布共享布局（在创建或更新时设置 `"is_shared": true`）需要全局**维护者**角色。

## 步骤 3：渲染小组件数据（可选）

通常您不需要自己渲染数据——仪表板在显示小组件时会自动完成这项工作。但同样的 `widget_data` 端点也可以直接调用，这对于需要引用实时数字的脚本或聊天摘要很有用。将小组件的 `config`（或其相关子集）作为请求负载发送即可。

**筛选后的计数**（`POST`）：

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_data/count/" \
  -d '{"model": "finding", "filters": {"status_any": "Active", "severity": "Critical"}}'
# → {"count": 42}
```

**分组聚合**（`POST`），即图表背后的数据：

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

`widget_data` 的完整操作集：

| 操作 | 方法 | 关键负载 / 参数 | 返回内容 |
|--------|--------|----------------------|---------|
| `count` | POST | `model`, `filters` | `{count}` |
| `aggregate` | POST | `model`, `filters`, `group_by`, `aggregation`, `time_bucket?`, `limit?` | `{labels, series, ...}` |
| `dimensions` | GET | `?model=` | 有效的分组维度 |
| `top_records` | POST | `model`, `filters`, `metric`, `limit?`, `sort?` | `{labels, series, ...}` |
| `record_metrics` | GET | `?model=` | 记录模式下的有效指标 |
| `rate_chart` | POST | `model`, `filters`, `pass_filters`, `group_by`, `limit?`, `sort?`, `min_denominator?`, `metric_label?` | 比率 / 分子 / 分母序列 |
| `sankey` | POST | `model?`, `filters`, `source_dim`, `target_dim` | `{nodes, links, ...}` |
| `sunburst` | POST | `model?`, `filters`, `hierarchy`（1–2 个维度） | `{tree, ...}` |
| `scan_coverage` | POST | `model?`, `filters`, `windows?` | 各时间窗口的区间数据 |
| `risk_matrix` | POST | `filters`, `x_dim?` | EPSS × 风险单元格（仅限发现项） |
| `priority_histogram` | POST | `filters`, `bin_count?` | 直方图分箱（仅限发现项） |
| `treemap` | POST | `filters`, `metric?` | 嵌套的组合树状图 |
| `heatmap` | POST | `filters`, `date_field?`, `window_days?` | 按天划分的日历单元格 |
| `aging` | POST | `filters`, `boundaries?`, `date_field?`, `severity_filter?` | 堆叠的账龄区间序列 |
| `mttr_mttd` | POST | `filters`, `time_bucket?`, `window_days?` | 成对的 MTTR/MTTD 序列 |
| `velocity` | POST | `filters`, `time_bucket?`, `window_days?` | 新建与已关闭对比序列 |
| `my_work` | GET | `?buckets=`, `?limit=` | 您的分配项 / 提及 / 待处理审核 |
| `sla_burndown` | GET | `?days_threshold=`, `?severity_filter=`, `?limit=`, `?include_overdue=` | 临近 SLA 违约的发现项 |
| `recent_activity` | GET | `?model=`, `?limit=` | 近期记录动态 |
| `saved_reports` | GET | `?limit=` | 已保存的报告模板 *(需要报告功能)* |
| `usage` | GET | — | 许可证使用情况明细 *(需要维护者角色)* |

## 综合示例：完整的生命周期脚本

下面的脚本仅使用 Python 3 标准库运行整个流程——不依赖 `requests`，也不依赖任何第三方包。它会从 `DD_IMPORTER_DOJO_API_TOKEN` 读取令牌，发现小组件目录，构建一个包含两个小组件的布局（`widgets` 列表与 `layout` 映射一并生成，确保它们的 ID 始终匹配），创建该布局，将其设为默认布局，读取回来进行验证，并将创建的 ID 写入 `created.json`。

设置您的实例 URL 并运行它：

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

## 验证您构建的内容

由于无效的筛选键会被静默丢弃，验证是工作流程中不可或缺的一环，而不是事后才想起来的补充步骤。

**确认布局按预期保存。** 通过 `GET` 读取回来，检查 `widgets` 和 `layout`：

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/layouts/12/"
```

对于每个小组件，将返回的 `config.filters` 与您发送的内容进行比对。如果预期的某个筛选条件缺失，说明该键对该模型而言不是有效的筛选条件——请对照该对象列表视图的筛选条件重新检查。如果您设置过，请确认 `is_default` 为 `true`，并确认 `layout` 中的每个键都对应一个小组件的 `id`。

**抽查小组件的数据。** 渲染其数据端点，确认数字符合预期：

```bash
curl -s -X POST \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" -H "Content-Type: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/dashboards/widget_data/count/" \
  -d '{"model": "finding", "filters": {"status_any": "Active", "severity": "Critical"}}'
```

**使用 PATCH 修复小组件。** 向 `/dashboards/layouts/{id}/` 发送包含完整 `widgets` 和 `layout` 的 `PATCH` 请求会将其整体替换——请发送完整的目标集合，而不是部分内容。

## 后续步骤

- 在[可自定义仪表板界面](../custom-dashboards/)中以交互方式构建和排列相同的布局。
- 借助[仪表板 LLM 集成](../custom-dashboards-llm/)，让 LLM 为您设计和构建仪表板。
