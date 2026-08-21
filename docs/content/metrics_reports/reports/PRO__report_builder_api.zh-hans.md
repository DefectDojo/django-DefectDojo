---
title: 使用 API 实现报告自动化
description: 创建主题、区块和模板,然后通过 DefectDojo Pro REST API 运行报告并下载结果
draft: false
audience: pro
weight: 21
slug: report-builder-api
---

<span style="background-color:rgba(242, 86, 29, 0.3)">注意:Report Builder REST API(报告主题、区块、模板和生成的报告)是 DefectDojo Pro 的功能,当前处于测试版(beta)阶段。</span>

报告构建器 REST API 可以让您自动化处理与在[报告构建器 UI](../report-builder/)中手动组装时相同的主题、区块和模板 —— 而且它更进一步,让您可以**运行**模板并**下载**生成的 PDF 或 HTML 文件。本指南将带您走完完整的生命周期:进行身份验证、发现字段和过滤器的相关术语、创建各个构建模块,然后生成并获取报告。

> **只需要快速导出发现项?** 如果您只需要以 JSON、HTML、CSV 或 Excel 格式导出一份扁平的发现项列表 —— 无需设置主题、区块或模板 —— 请使用更简单的 `generate_report/` 端点,相关文档参见[生成报告](/automation/api/api-v2-docs/#generating-reports)。本页介绍的报告构建器 API 用于构建具有设计感的多区段报告。

## 身份验证

每个请求都通过 `Authorization` 请求头中携带的个人 API 令牌进行身份验证,前缀使用 `Token`(而不是 `Bearer`)。

在 DefectDojo Pro UI 的 **User Settings → API v2 Key** 中获取您的令牌。将其存储在环境变量中,确保它不会出现在您的 shell 历史记录或已提交的脚本中:

```bash
export DD_IMPORTER_DOJO_API_TOKEN="YOUR_API_TOKEN"
```

所有调用的基础 URL 是您的实例地址加上 `/api/v2`:

```text
https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2
```

所需的请求头:

| 请求头 | 值 | 适用场景 |
|--------|-------|------|
| `Authorization` | `Token YOUR_API_TOKEN` | 每个请求 |
| `Accept` | `application/json` | 每个请求 |
| `Content-Type` | `application/json` | 带 JSON 请求体的 `POST` / `PATCH` |

一个最简单的已认证请求示例如下:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_themes/"
```

列表类端点通过 `limit` 和 `offset` 查询参数进行分页。

> **⚠️ Security Notice:** 您的 API 令牌可完全访问您的 DefectDojo 数据。切勿将其粘贴到聊天记录、截图、工单或已提交的文件中。请从环境变量中读取该令牌,一旦泄露立即轮换,并尽可能将令牌限定给服务账号使用。

## 报告 API 概览

报告构建器 API 由四种资源组成。每种资源都支持标准的列表(`GET`)、创建(`POST`)、获取(`GET {id}/`)、更新(`PATCH {id}/`)和删除(`DELETE {id}/`)操作,此外还提供少量自定义操作。

| 资源 | 路径 | 说明 | 自定义操作 |
|----------|------|------------|----------------|
| 主题(Themes) | `/report_themes/` | 颜色、字体、页眉/页脚图片、页码 | — |
| 区块(Blocks) | `/report_blocks/` | 单个内容片段:封面页、表格或详情区段 | `field_options/`、`preview/`、`{id}/preview/`、`{id}/duplicate/` |
| 模板(Templates) | `/report_templates/` | 由多个区块加一个主题组成的有序列表 | `{id}/duplicate/` |
| 生成的报告(Generated reports) | `/generated_reports/` | 模板的一次运行,生成可下载的文件 | `{id}/download/` |

另外两个端点可以帮助您发现所需的术语:

| 端点 | 用途 |
|----------|---------|
| `GET /report_blocks/field_options/` | 每个模型可用的列字段路径及排序选项 |
| `GET /oa3/schema/?format=json` | 完整的 OpenAPI schema —— 用于发现有效的过滤器名称 |

## 第 1 步:发现可用术语

如果凭猜测来配置区块,有两处很容易出错:您列出的**列字段**,以及您应用的**过滤器**。API 为这两者都提供了权威数据源。请先获取这些信息,再依据服务器实际接受的内容进行构建。

### 列字段与排序

`field_options` 会返回可放入表格型或详情型区块的每个模型的有效 `fields`(列路径)和 `ordering_fields`(排序字段):

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_blocks/field_options/"
```

响应的结构大致如下(已截断):

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

区块的 `fields` 列表只能使用此处返回的 `path` 值。有些路径是长文本或 markdown 格式,适合用于**详情型(detail)**区块,而不适合窄列的表格型区块 —— `field_options` 是权威列表,请以它为准进行核对,而不要硬编码一份详尽的字段集合。

### 从 schema 中获取过滤器名称

区块的过滤器存放在 `filter_entries` 中,其中每一项都是一个 `{field, value}` 键值对。有效的 `field` 名称是对应实体 REST 端点的 **GET 查询参数名称** —— *而不是* 您在界面中看到的标签文字。可以通过读取 OpenAPI schema 来发现这些名称:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/oa3/schema/?format=json" \
  > schema.json
```

然后查看您要筛选的实体对应的 GET 参数。对于发现项(findings),请查看 `paths` → `/api/v2/findings/` → `get` → `parameters`。与之类似的端点还有:**资产(assets)**(原称 Products)对应 `/api/v2/assets/`,**组织(organizations)**(原称 Product Types)对应 `/api/v2/organizations/`,以及 `/api/v2/engagements/`、`/api/v2/tests/`、`/api/v2/test_types/` 和 `/api/v2/risk_acceptance/`。每个参数的 `name` 都是一个有效的过滤器 `field`。

> **💡 Tip:** 在 DefectDojo Pro 中,**Assets(资产)** 曾经叫做 **Products(产品)**,**Organizations(组织)** 曾经叫做 **Product Types(产品类型)**。尽管这些实体现已更名为 Assets 和 Organizations,但发现项上底层的过滤器字段路径仍沿用旧的 `product` 命名方式(例如 `test__engagement__product`)。

> **🔑 Important:** 对于 `field` 不是该模型真实 GET 参数的任何 `filter_entry`,服务器都会**静默丢弃**。系统不会报错 —— 该过滤器只是不会出现在保存后的区块中。创建区块后请务必再次 GET 该区块,并将返回的 `filter_entries` 与您发送的内容进行比对。

### 常用过滤器字段

下表列出了经过验证、实用价值较高的过滤器。所有的值都以**单一字符串**形式发送;布尔值使用字面字符串 `"true"` / `"false"`。

**发现项过滤器**

| 字段 | 示例值 | 说明 |
|-------|---------------|-------|
| `active` | `"true"` | 布尔字符串 |
| `verified` | `"true"` | 布尔字符串 |
| `is_mitigated` | `"false"` | 布尔字符串 |
| `risk_accepted` | `"false"` | 布尔字符串 |
| `duplicate` | `"false"` | 布尔字符串 |
| `false_p` | `"false"` | 布尔字符串 |
| `out_of_scope` | `"false"` | 布尔字符串 |
| `severity` | `"Critical"` | 仅支持单个值 —— **不支持**逗号分隔的多个值。每个严重程度请使用单独的区块。 |
| `known_exploited` | `"true"` | 布尔字符串 |
| `ransomware_used` | `"true"` | 布尔字符串 |
| `outside_of_sla` | `"1"` | **数字**字符串,不是布尔字符串 |
| `priority_min` | `"800"` | 使用 `_min`/`_max`,而不是 `_greater_than` |
| `priority_max` | `"1000"` | 使用 `_min`/`_max` |
| `tag` | `"DR"` | 单个标签 |
| `tags` | `"kev,pci"` | 任一匹配(匹配所列标签中的任意一个) |
| `tags__and` | `"kev,pci"` | 全部匹配(必须匹配所列的每一个标签) |
| `test__engagement__product` | `"42"` | 资产 ID(Assets 原称 Products) |
| `test__engagement__product__prod_type` | `"3"` | 组织 ID(原称 Product Type) |
| `cve` | `"CVE-2024-12345"` | |
| `cwe` | `"79"` | |
| `date_after` | `"2025-12-31"` | |
| `date_before` | `"2025-12-31"` | |
| `planned_remediation_date_before` | `"2025-12-31"` | |

**资产过滤器**(Assets 原称 Products;以下为 `/api/v2/assets/` 上的参数)

| 字段 | 示例值 | 说明 |
|-------|---------------|-------|
| `business_criticality` | `"very_high"` | |
| `internet_accessible` | `"true"` | 布尔字符串 |
| `lifecycle` | `"production"` | |
| `platform` | `"web"` | |
| `tag` | `"pci"` | 单个标签 |

**风险接受过滤器**

| 字段 | 示例值 | 说明 |
|-------|---------------|-------|
| `decision` | `"Accept (Transfer)"` | |
| `owner` | `"7"` | 用户 ID |
| `expiration_date_before` | `"2025-12-31"` | 该模型不存在 `tag` 过滤器 |

对于**测试活动(engagement)**、**测试(test)**、**测试类型(test type)** 和**组织(organization)** 区块,请按照上文所述直接从 schema 中读取 GET 参数。较为常用的包括测试上的 `engagement__product` 和 `status`,以及测试类型上的 `name` —— 但在依赖某个名称之前,请务必先在 `schema.json` 中确认其确切名称。

> **⚠️** 以下这些遗留/界面风格的名称会被**静默丢弃**,请勿使用:`status_any`、`priority_greater_than`、`severity__in`、`mitigated_within_sla`,以及任何**逗号分隔的 `severity`** 值(例如 `"Critical,High"`)。请改用 schema 中的真实查询参数名称,并将多严重程度的需求拆分为多个区块。

> **🔑 Important:** 包含 `filter_entries` 的 `PATCH` 请求会**替换整个列表** —— 不会进行合并。每次更新时都请发送完整的目标过滤器集合,否则遗漏的过滤器会被丢弃。

## 第 2 步:创建主题、区块和模板

请按照依赖顺序构建这些组成部分:先创建**主题**,再创建**区块**,最后创建同时引用两者的**模板**。

### 创建主题

颜色为 7 个字符的十六进制字符串。任何省略的字段都会回退到其默认值(主色 `#1e3a5f`,辅助色 `#4a90a4`,强调色 `#e67e22`,文字色 `#333333`,背景色 `#ffffff`)。

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

响应中包含新主题的 `id`。页眉和页脚图片是可选的,以 multipart 表单字段(`header_image` / `footer_image`)形式上传;上面的 JSON 示例中省略了它们。

### 创建区块

一个区块包含 `name`、`block_type` 以及与之对应的配置对象。支持的 `block_type` 取值为 `stock`、`tabular` 和 `detail`。(数据模型中还存在 `chart` 类型,但目前尚未通过 API 开放。)

**固定内容(stock)封面页。** stock 类型的区块承载固定内容。`stock_type` 取值为 `cover_page`、`table_of_contents`、`page_break`、`image` 或 `text_block` 之一。

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

**带过滤器的表格型发现项区块。** 表格型(tabular)区块用于渲染所选模型的多行数据。`model_choice` 只能是 `organization`、`asset`、`engagement`、`test`、`finding`、`test_type` 或 `risk_acceptance` 中的一个。`fields` 取自 `field_options`(请核对每个 `path`),`filter_entries` 用于限定行的范围。

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

**详情型发现项区块。** 详情型(detail)区块会为每条记录渲染一个展开的区段,可以包含不适合放入窄表格列的长文本/markdown 字段。同样,请对照 `field_options` 核对 `fields`。

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

每个区块的响应中都包含其 `id`。请注意,`filter_entries` 返回的是服务器实际存储的内容 —— 请将其与您发送的内容进行比对(参见[验证您构建的内容](#verify-what-you-built))。

### 创建模板

模板将一个主题与一份有序的区块列表绑定在一起。只读字段是 `template_blocks`;在创建和更新时,您需要**写入**的字段是 `template_blocks_write`。每一项都需要包含 `order` 和 `block_id`,同一个 `block_id` 可以出现多次。

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

请将 `theme_id` 和每个 `block_id` 替换为前面步骤中返回的 ID。响应中包含模板的 `id`。

## 第 3 步:运行报告并下载结果

生成报告是异步的:您先创建一次运行,轮询其状态,待完成后再下载文件。

**启动一次运行。** 通过 POST 提交 `template_id` 以及取值为 `pdf` 或 `html` 的 `file_format`:

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

响应会返回新报告的 `id`,其 `status` 为 `pending`。

**轮询状态。** 反复获取该报告,直到其 `status` 到达终态。流程为 `pending` → `processing` → `completed`。若为 `failed`,请查看 `error_message` 了解原因。

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/generated_reports/7/"
```

**下载文件。** 一旦 `status` 变为 `completed`,下载端点便会以附件形式返回文件。在此之前,该端点会返回 `404`。

```bash
curl -s -L \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/generated_reports/7/download/" \
  -o report.pdf
```

## 整合示例:完整生命周期脚本

下面这个脚本仅使用 Python 3 标准库运行完整流程 —— 不依赖 `requests`,也不依赖任何第三方包。它会从 `DD_IMPORTER_DOJO_API_TOKEN` 读取令牌,创建一个主题、三个区块和一个模板,启动一次报告运行,以退避方式轮询直至完成或失败,下载结果,并将创建出的各项 ID 写入 `created.json`。

设置好您的实例 URL 后运行该脚本:

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

## 验证您构建的内容

由于无效的过滤器会被静默丢弃,验证是工作流程的一部分,而不是事后才想起来做的事情。

**确认区块的过滤器已生效保留。** 重新 GET 每个区块,并将其 `filter_entries` 与您 POST 时发送的内容进行比对:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_blocks/11/"
```

如果您发送的某个过滤器没有出现在 `filter_entries` 中,说明它的 `field` 名称不是该模型有效的 GET 参数 —— 请在 `schema.json` 中重新核实该名称。

**确认模板顺序和主题。** GET 该模板,检查 `template_blocks` 中列出的区块顺序(`order`)是否符合预期,以及绑定的主题是否正确:

```bash
curl -s \
  -H "Authorization: Token ${DD_IMPORTER_DOJO_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://[YOUR-INSTANCE].cloud.defectdojo.com/api/v2/report_templates/5/"
```

**通过 PATCH 修复被丢弃的过滤器。** 要修正某个区块的过滤器,请 PATCH 提交**完整**的目标过滤器集合 —— PATCH 会整体替换 `filter_entries`:

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

## 后续步骤

- 您也可以在[报告构建器 UI](../report-builder/)中以交互方式构建和预览相同的主题、区块和模板。
- 借助[报告构建器 LLM 集成](../report-builder-llm/),让 LLM 为您组装报告配置。
