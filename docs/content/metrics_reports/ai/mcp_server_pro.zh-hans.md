---
title: MCP 服务器
description: DefectDojo 的 MCP 服务器允许您在 DefectDojo Pro 中使用 LLM
draft: false
audience: pro
weight: 23
aliases:
- /zh-hans/en/ai/mcp_server_pro
---

<span style="background-color:rgba(242, 86, 29, 0.3)">注意：AI 功能仅在 DefectDojo Pro 中提供。</span>

DefectDojo 模型上下文协议（MCP）服务器使大语言模型（LLM）能够智能地与 DefectDojo 的漏洞管理数据交互。与仅仅传输数据的传统 API 集成不同，MCP 服务器提供结构化的上下文和语义信息，使 AI 助手能够执行复杂的安全分析并生成可操作的洞察。

- **结构化上下文：** MCP 为 DefectDojo 数据赋予语义，而不只是传输原始数据
- **预处理数据：** DefectDojo 经过标准化、去重的数据消除了 LLM 的预处理负担
- **业务智能集成：** 将技术性漏洞数据与业务背景相结合
- **可用于高层汇报的分析：** 生成适合从技术团队到高层管理者各层级使用的报告
- **10 倍复合价值：** AI 增强分析所提供的价值呈指数级超过人工查询

> **🔑 重要提示：** MCP 服务器端点位于 `/mcp`，但所有函数调用均使用 DefectDojo 的基础 URL。这种分离确保了对漏洞数据的安全、结构化访问。

## Connect To MCP

### Prerequisites

- 已启用 MCP 服务器的 DefectDojo 实例（v2.51.2 或更高版本）
- 具有相应权限的有效 DefectDojo API 令牌
- AI 提供方：Claude、ChatGPT、Gemini 或其他兼容 MCP 的自定义客户端

> **⚠️ 安全提示：** 您的 API 令牌是用于身份验证和授权的高度敏感信息。在分享配置或截图时，**切勿在任何请求或响应中显示该令牌**。

### Connection Methods

根据您所使用的 AI 界面不同，连接 DefectDojo MCP 服务器有**两种不同的方式**：

#### Method 1: Configuration File Method

**适用对象：** Claude Desktop、MCP Inspector 及其他桌面端 MCP 客户端

**工作原理：**
- 令牌和连接详情存储在配置文件中
- 启动应用程序时自动建立连接
- 无需在对话中粘贴说明
- MCP 服务器在所有对话中始终可用

**优势：** 一次设置，随处可用。安全性更高（令牌不会出现在聊天记录中）。

#### Method 2: Manual Prompt Method

**适用对象：** Claude.ai 网页界面、ChatGPT 网页界面（配合插件）、Gemini 网页界面

**工作原理：**
- 您需要在每次对话开始时复制/粘贴连接说明
- 或将说明添加到 Claude Project 中以自动包含
- AI 读取说明后连接到 MCP 服务器
- 每次新对话都需要重新提供说明

**优势：** 无需安装软件即可在网页浏览器中使用。

> **💡 应该使用哪种方式？** 如果您有支持配置文件的桌面应用，请使用 **Method 1 (Configuration File)**。如果您使用的是网页浏览器界面，请使用 **Method 2 (Manual Prompt)**。

### MCP Server Connection Details

所有方式均使用以下核心参数：

| Parameter | Value | Notes |
|-----------|-------|-------|
| **Transport Type** | `Streamable HTTP` | ⚠️ SSE (Server-Sent Events) is deprecated |
| **MCP Endpoint URL** | `https://[YOUR-INSTANCE].defectdojo.com/mcp` | Used for establishing MCP connection |
| **Base URL for Functions** | `https://[YOUR-INSTANCE].defectdojo.com/` | Used in all tool function calls |
| **Authentication** | `Authorization: Token [YOUR_API_TOKEN]` | ⚠️ Use "Token" prefix, not "Bearer" |

## Quick Start Guides by AI Provider

<details>
<summary><h3>🖥️ Claude Desktop (Method 1: Configuration File)</h3></summary>

**Step 1: 找到配置文件**

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`

**Step 2: 编辑配置文件**

在 `mcpServers` 部分添加或更新您的 DefectDojo 实例详情：

```json
{
  "mcpServers": {
    "DefectDojo-MCP": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://your-instance.defectdojo.com/mcp",
        "--header",
        "Authorization: Token YOUR_API_TOKEN"
      ]
    }
  }
}
```

> **⚠️ Critical:** 带身份验证信息的 `--header` 标志是必需的。请将 `YOUR_API_TOKEN` 替换为您实际的 DefectDojo API 令牌。

**Step 3: 重启 Claude Desktop**

关闭并重新打开 Claude Desktop 以使更改生效。

**Step 4: 验证连接**

开始一个新对话并提问：`"Can you connect to DefectDojo?"`

如果连接成功，Claude 会确认它已获得 DefectDojo MCP 服务器工具的访问权限。

> **✅ Done!** DefectDojo MCP 服务器现已在所有对话中可用，无需再粘贴说明。

</details>

<details>
<summary><h3>🌐 Claude.ai Web Interface (Method 2: Manual Prompt)</h3></summary>

Claude.ai 网页界面不支持配置文件。您需要在每次对话中提供连接说明，或使用 Claude Project。

#### Option A: Paste Instructions Per Conversation

**Step 1: 复制以下说明**

```
For this project, use the DefectDojo MCP server with these parameters in ALL function calls:

- **URL:** https://your-instance.defectdojo.com/ (base URL, NOT the /mcp endpoint)
- **Token:** YOUR_API_TOKEN
- **IMPORTANT:** DO NOT SHOW THE TOKEN IN ANY REQUESTS OR RESPONSES

The MCP server connects to https://your-instance.defectdojo.com/mcp but function calls must use the base URL.

**Do not show any of the API requests or responses.**
```

**Step 2: 开始新对话**

在对话开头粘贴说明，然后提出您的安全问题。

**Step 3: 每次新对话都重复此操作**

每次新对话开始时都必须包含这些说明。

#### Option B: Use a Claude Project (Recommended)

**Step 1: 创建一个 Claude Project**

- 在 Claude.ai 中，点击左侧边栏的 "Projects"
- 点击 "Create Project"
- 将其命名为 "DefectDojo Security Analysis"

**Step 2: 向该 Project 添加自定义说明**

在 Project Settings → Custom Instructions 中粘贴：

```
For this project, use the DefectDojo MCP server with these parameters in ALL function calls:

- **URL:** https://your-instance.defectdojo.com/
- **Token:** YOUR_API_TOKEN
- **IMPORTANT:** DO NOT SHOW THE TOKEN IN ANY REQUESTS OR RESPONSES

The MCP server connects to https://your-instance.defectdojo.com/mcp but function calls must use the base URL.

Do not show any of the API requests or responses.
```

**Step 3: 所有 DefectDojo 相关对话均使用该 Project**

该 Project 内的所有对话都将自动获得 DefectDojo MCP 服务器的访问权限。

> **✅ Done!** 在此 Project 中工作时，Claude 会自动获得 DefectDojo MCP 访问权限。

</details>

<details>
<summary><h3>💬 ChatGPT (Method 2: Manual Prompt)</h3></summary>

> **⚠️ Note:** 相较于 Claude，ChatGPT 对 MCP 的支持较为有限。原生 MCP 集成可能需要 ChatGPT Plus 或 Enterprise 版本以及特定的插件配置。

**Step 1: 检查 MCP 插件可用性**

在 ChatGPT 中，检查您的插件商店中是否提供 MCP 或 API 连接器插件。MCP 支持情况因订阅套餐而异。

**Step 2: 复制连接说明**

```
I need you to connect to a DefectDojo MCP server with these details:

MCP Endpoint: https://your-instance.defectdojo.com/mcp
Base URL for API calls: https://your-instance.defectdojo.com/
Authentication: Authorization header with value "Token YOUR_API_TOKEN"

Use this connection to access DefectDojo vulnerability data. The server provides tools for:
- Getting findings with severity, status, and date filters
- Accessing products, engagements, tests
- User and group management
- Analyzing security trends

Do not show the API token in responses.
```

**Step 3: 在每次对话开始时粘贴**

在开始关于 DefectDojo 安全分析的新对话时包含这些说明。

**Alternative: Use Custom GPT**

如果您拥有 ChatGPT Plus，可以创建一个在说明中包含 DefectDojo 连接详情的 Custom GPT，以便重复使用。

</details>

<details>
<summary><h3>💎 Google Gemini (Method 2: Manual Prompt)</h3></summary>

> **⚠️ Note:** Gemini 对 MCP 的支持仍在完善中，原生集成可能有限。如需完整功能，请考虑使用配合 MCP 客户端库的 Gemini API。

**Step 1: 复制连接说明**

```
Connect to DefectDojo vulnerability management system via MCP server:

MCP Server: https://your-instance.defectdojo.com/mcp
API Base URL: https://your-instance.defectdojo.com/
Authentication: Token YOUR_API_TOKEN (use Authorization header with "Token" prefix)

Available capabilities:
- Query findings by severity (Critical, High, Medium, Low, Info)
- Filter by status (Active, Verified, False Positive, etc.)
- Filter by date ranges (Today, Past 7/30/90 days, etc.)
- Access products, engagements, tests, users, groups
- Generate security analysis and reports

Important: Do not display the authentication token in responses.
```

**Step 2: 连同说明一起开始对话**

在处理 DefectDojo 数据时，每次新的 Gemini 对话都以这些说明开头。

**For Advanced Users:**

如需具备完整 MCP 协议支持的编程访问，请考虑使用配合 MCP 客户端库（Python、JavaScript）的 Gemini API。

</details>

<details>
<summary><h3>🔍 MCP Inspector (Testing & Validation)</h3></summary>

**Use Case:** 在与 AI 助手配合使用之前，测试您的 DefectDojo MCP 连接、探索可用工具并验证配置。

**Step 1: 安装 MCP Inspector**

```bash
# macOS (using Homebrew)
brew install mcp-inspector

# Or using npm (all platforms)
npm install -g @modelcontextprotocol/inspector
```

**Step 2: 运行 MCP Inspector**

```bash
mcp-inspector
```

这将启动一个本地网页服务器（通常位于 `http://localhost:6274`）

**Step 3: 在网页界面中配置连接**

- **Transport Type:** `Streamable HTTP`
- **URL:** `https://your-instance.defectdojo.com/mcp`
- **Connection Type:** `Via Proxy`
- **Custom Headers:**
  - Name: `Authorization`
  - Value: `Token YOUR_API_TOKEN`
  - **Important:** 启用请求头旁边的开关

**Step 4: 点击 "Connect"**

连接成功后，您可以浏览：

- **Tools tab:** 查看全部 12 个可用工具及其参数
- **Prompts tab:** 查看预配置的提示词模板
- **Resources tab:** 查看可用的数据资源

> **✅ Perfect for:** 在配置 AI 助手之前验证配置是否有效、探索工具能力，以及排查连接问题。

</details>

---

> **✅ Connection Successful?** 通过任意一种方式连接后，向您的 AI 助手提问以测试：`"How many active findings do we have in DefectDojo?"`

---

## Available Tools Reference

DefectDojo MCP 服务器提供 12 个工具，用于访问和分析漏洞数据。每个工具都包含智能的参数处理机制，并返回针对 LLM 分析优化的结构化数据。

> **💡 Parameter Note:** 所有工具均接受一个可选的 `token` 参数。如果在单次调用中未提供，LLM 将使用连接配置中的令牌。

---

### 🔍 Findings Analysis Tools

<details>
<summary><h4>get_findings</h4></summary>

**Description:** 从 DefectDojo 检索发现项，支持复杂的过滤功能。这是漏洞分析中最强大、使用频率最高的工具。

**Parameters:**

**severity** (Optional)
- **Type:** 字符串数组
- **Values:** `Critical`, `High`, `Medium`, `Low`, `Info`
- **Example:** `["Critical", "High"]`
- **Usage:** 按严重程度过滤发现项。可提供多个值以进行组合查询。

**status** (Optional)
- **Type:** 字符串数组
- **Values:** `Any`, `Active`, `Open`, `Verified`, `Out of Scope`, `False Positive`, `Inactive`, `Risk Accepted`, `Closed`, `Under Review`
- **Example:** `["Active", "Verified"]`
- **Usage:** 按当前状态过滤发现项。使用 `Active` 可聚焦于当前的风险评估。

**date** (Optional)
- **Type:** 包含单个字符串值的数组
- **Values:** `0 - Any date`, `1 - Today`, `2 - Past 7 days`, `3 - Past 30 days`, `4 - Past 90 days`, `5 - Current month`, `6 - Current year`, `7 - Past year`
- **Example:** `["3 - Past 30 days"]`
- **Usage:** 按发现日期过滤发现项。仅允许提供一个值。

**limit** (Optional)
- **Type:** 数字
- **Default:** 100
- **Range:** 1-100
- **Usage:** 要返回的发现项数量。如只需计数，可设为 1 并使用响应中的 count 属性。

**offset** (Optional)
- **Type:** 数字
- **Default:** 0
- **Usage:** 用于检索更多结果的分页偏移量。

> **💡 Best Practice:** 对于风险评估类查询，请始终使用 `status: ["Active"]`，以便聚焦于当前尚未解决的漏洞，而非历史数据。

**Example Query:**

**User asks:** "Show me all Critical and High severity active findings from the past 30 days"

**LLM calls:**
```
get_findings({
  severity: ["Critical", "High"],
  status: ["Active"],
  date: ["3 - Past 30 days"],
  limit: 100
})
```

</details>

<details>
<summary><h4>get_finding_by_id</h4></summary>

**Description:** 通过唯一标识符检索某个特定发现项的详细信息。

**Parameters:**

**finding_id** (Required)
- **Type:** 数字
- **Minimum:** 1
- **Usage:** 要检索的发现项的唯一 ID。

**Example Query:**

**User asks:** "Get details for finding #1234"

**LLM calls:** `get_finding_by_id({ finding_id: 1234 })`

</details>

---

### 📦 Product & Engagement Tools

<details>
<summary><h4>get_products</h4></summary>

**Description:** 检索 DefectDojo 中的所有产品。产品代表正在被测试的应用程序、服务或系统。

**Parameters:**

**limit** (Optional)
- **Default:** 100
- **Usage:** 要返回的产品最大数量。

**offset** (Optional)
- **Default:** 0
- **Usage:** 分页偏移量。

</details>

<details>
<summary><h4>get_product_types</h4></summary>

**Description:** 检索 DefectDojo 中的产品类型分类。产品类型有助于将产品组织成逻辑分组。

**Parameters:** Same as `get_products`

</details>

<details>
<summary><h4>get_engagements</h4></summary>

**Description:** 检索安全测试活动。测试活动代表某个产品特定的测试活动或时间段。

**Parameters:** Same as `get_products`

</details>

<details>
<summary><h4>get_tests</h4></summary>

**Description:** 检索 DefectDojo 中的安全测试。测试包含来自特定安全工具或人工测试的扫描结果。

**Parameters:** Same as `get_products`

</details>

---

### 👥 User & Access Management Tools

<details>
<summary><h4>get_users</h4></summary>

**Description:** 检索 DefectDojo 中的所有用户，用于干系人分析和责任归属映射。

**Parameters:**

**limit** (Optional)
- **Default:** 100

**offset** (Optional)
- **Default:** 0

</details>

<details>
<summary><h4>get_user_by_id</h4></summary>

**Description:** 检索某个特定用户的详细信息。

**Parameters:**

**user_id** (Required)
- **Type:** 数字
- **Minimum:** 1

</details>

<details>
<summary><h4>get_groups</h4></summary>

**Description:** 检索用户组，用于组织结构分析和权限映射。

**Parameters:** Same as `get_users`

</details>

<details>
<summary><h4>get_group_by_id</h4></summary>

**Description:** 检索某个特定组的详细信息。

**Parameters:**

**group_id** (Required)
- **Type:** 数字
- **Minimum:** 1

</details>

<details>
<summary><h4>get_dojo_group_members</h4></summary>

**Description:** 检索某个特定组的所有成员，用于团队分析。

**Parameters:**

**group_id** (Required)
- **Type:** 数字
- **Minimum:** 1

**limit** (Optional)
- **Default:** 100

**offset** (Optional)
- **Default:** 0

</details>

<details>
<summary><h4>get_roles</h4></summary>

**Description:** 检索 DefectDojo 中的角色定义，用于了解权限结构。

**Parameters:** Same as `get_users`

</details>

---

## Pre-Configured Prompts

DefectDojo MCP 服务器包含针对常见分析场景的最佳实践预配置提示词。这些提示词可由您的 AI 助手直接调用。

### 🛡️ SAST Review Report

**Purpose:** 基于 DefectDojo 数据创建一份全面的报告，评估 SAST（静态应用安全测试）工具的有效性。

**Generated Analysis Includes:**

- 按工具和漏洞类型划分的误报率
- 按严重程度划分的平均修复时间
- 多次出现的严重漏洞（去重缺口）
- 开发团队绩效对比
- 工具配置改进建议
- 从重复出现的漏洞模式中识别出的培训缺口
- 当前工具方案与推荐工具方案的成本分析

**Output Format:** HTML 格式的技术评估报告，适用于为安全工具预算申请提供依据。

### 📊 Security Landscape Report

**Purpose:** 基于 DefectDojo 数据创建一份仪表板式报告，概览安全态势，适用于季度董事会会议。

**Generated Analysis Includes:**

- 过去 90 天的漏洞趋势
- 严重/高危发现项最多的开发团队
- 按产品和产品类型划分的风险敞口
- 需要立即关注的前 5 个 CWE 类别
- 具体的修复措施及成本收益分析
- 改善安全态势的 6 个月路线图

**Output Format:** 面向高层的 HTML 报告，包含可视化元素、统计卡片，并聚焦业务风险。

> **💡 Using Prompts:** 要调用某个提示词，只需向您的 AI 助手提问："Create a SAST Review Report" 或 "Generate a Security Landscape Report using DefectDojo data"

---

## Use Case Examples

### Use Case 1: Executive Security Dashboard

**Scenario:** CISO 需要为董事会汇报准备季度安全指标

**User Prompt:**

```
"Create an executive security dashboard for our Q4 board meeting showing:
- Total vulnerability counts by severity
- Trends over the past 90 days  
- Which products have the highest risk exposure
- Top 5 vulnerability categories needing attention
- Specific remediation recommendations with ROI
- A 6-month roadmap for improving our security posture"
```

**What happens behind the scenes:**

1. `get_findings` - 获取活动发现项总数
2. `get_findings` - 严重和高危级别分析
3. `get_findings` - 90 天趋势数据
4. `get_products` - 产品漏洞分布
5. `get_engagements` - 近期测试活动

**Generated Output:** 面向高层的 HTML 报告，包含漏洞趋势、按产品划分的风险敞口、排名前列的 CWE 类别、附带 ROI 的具体修复措施，以及 6 个月的安全路线图。

---

### Use Case 2: Developer Team Performance Analysis

**Scenario:** 工程经理希望了解哪些团队需要额外的安全培训

**User Prompt:**

```
"Which development teams have the most security findings? What types of vulnerabilities 
are they creating repeatedly? Based on this analysis, recommend specific security 
training programs for each team."
```

**What happens behind the scenes:**

1. `get_findings` - 所有活动发现项
2. `get_products` - 将发现项与产品/团队关联
3. `get_groups` - 团队组织结构
4. `get_users` - 个人开发者责任归属

**Analysis Delivered:** 按团队分组的发现项、显示重复错误的 CWE 模式分析、培训缺口识别，以及针对每个团队的定向安全培训建议。

---

### Use Case 3: Tool Effectiveness Assessment

**Scenario:** 安全团队正在评估当前 SAST 工具的投资回报率

**User Prompt:**

```
"Analyze the effectiveness of our SAST tools. Show me false positive rates, 
mean time to remediation, which tools find the most valuable vulnerabilities, 
and recommend configuration improvements or alternative tools."
```

**What happens behind the scenes:**

1. `get_tests` - 按工具划分的所有安全测试
2. `get_findings` - 误报分析
3. `get_findings` - 按工具划分的活动发现项
4. `get_findings` - 用于修复模式分析的已关闭发现项

**Analysis Delivered:** 按工具划分的误报率、按严重程度划分的平均修复时间、重复发现项分析、工具配置建议、培训缺口，以及备选工具方案的成本收益分析。

---

### Use Case 4: Compliance Reporting

**Scenario:** 为需要提供漏洞管理证据的 SOC 2 审计做准备

**User Prompt:**

```
"Generate a SOC 2 compliance report showing our vulnerability management processes, 
including discovery and remediation procedures, SLA compliance, continuous monitoring 
evidence, and accountability documentation."
```

**What happens behind the scenes:**

1. `get_findings` - 严重/高危活动发现项
2. `get_findings` - 年初至今的发现趋势
3. `get_engagements` - 测试频率与覆盖范围
4. `get_users` - 修复责任归属

**Analysis Delivered:** 漏洞发现与修复流程、SLA 合规跟踪、持续监控证据、责任归属文档，以及审计前需要修复的缺口。

---

### Use Case 5: Risk Prioritization

**Scenario:** 安全团队资源有限，需要为修复工作确定优先级

**User Prompt:**

```
"What are the highest priority vulnerabilities we should fix first? Consider severity, 
how long they've been open, exploitability, and business impact. Give me a prioritized 
remediation roadmap with effort estimates."
```

**What happens behind the scenes:**

1. `get_findings` - 严重/高危活动发现项
2. `get_products` - 业务重要性背景
3. 分析存续时间指标（自发现以来的天数）
4. 与 EPSS 分数（利用预测）进行交叉比对

**Analysis Delivered:** 综合严重程度、存续时间、可利用性和业务影响的风险排序漏洞清单，附带工作量估算和预期风险降低效果的具体修复路线图。

---


## Best Practices & Query Patterns

### Progressive Data Loading Strategy

您的 AI 助手会自动遵循以下数据加载模式来优化性能：

**1. Start with Summary Data**

在请求详细分析之前先询问计数：

```
"How many critical and high severity findings do we have?"
```

您的 AI 助手会使用 `get_findings` 工具并配合 `limit: 1`，以高效地仅获取计数。

**2. Use Strategic Pagination**

对于大型数据集，您的 AI 助手会自动分页浏览结果：

```
"Analyze all our active vulnerabilities"
```

如有需要，AI 会进行多次调用，从合理的限制值开始，并按需增加。

**3. Efficient Data Reuse**

按顺序提出相关问题，以避免重复查询：

```
"Show me all critical findings, then tell me which CWE categories they fall into"
```

AI 会复用第一次查询中获取的发现项数据用于 CWE 分析。

### Smart Filtering Strategies

设计您的提示词以充分利用 DefectDojo 强大的过滤能力：

#### Severity-Based Queries

**User Prompt:**
```
"Show me all Critical and High severity issues that need immediate attention"
```

**Behind the scenes:** AI 使用 `get_findings` 并配合严重程度和状态过滤条件

#### Time-Based Queries

**User Prompt:**
```
"What new vulnerabilities have been discovered in the past 30 days?"
```

**Behind the scenes:** AI 应用"过去 30 天"的日期过滤条件，并配合活动状态

#### Combined Filtering

**User Prompt:**
```
"Give me a risk assessment of all critical and high active findings from the past 90 days"
```

**Behind the scenes:** AI 结合严重程度、状态和日期过滤条件进行全面分析

### Cross-Reference Analysis

您的 AI 助手会自动将发现项与组织背景关联起来。只需提出综合性的问题：

**User Prompt:**
```
"Which products have the most critical vulnerabilities and who is responsible for fixing them?"
```

**Behind the scenes:** AI 将发现项 → 测试 → 测试活动 → 产品 → 用户/组 关联起来，以获得完整背景

### Vulnerability Intelligence Analysis

**CWE Pattern Analysis**

**User Prompt:**
```
"What are the most common vulnerability types in our codebase and which teams are creating them?"
```

AI 会按 CWE 对发现项分组，以识别重复出现的模式、培训需求和架构问题。

**Aging Metrics**

**User Prompt:**
```
"How long have our critical vulnerabilities been open? Which ones are overdue for remediation?"
```

AI 会计算自发现以来经过的时间，并标记出超出 SLA 阈值的发现项。

**Vulnerability Density**

**User Prompt:**
```
"Which products have the highest vulnerability density and represent the greatest risk?"
```

AI 会计算每个产品的发现项数量，并生成结合严重程度和数量的风险评分。

### Report Enhancement Standards

#### Always Include

- **Specific metrics:** 按严重程度划分的实际计数，而非笼统概述
- **CWE analysis:** 排名前列的漏洞类型及其说明
- **Aging data:** 漏洞已开放的时长
- **Actionable recommendations:** 附带时间安排的后续行动
- **ROI calculations:** 相关行动的预期成本与收益
- **Success metrics:** 如何衡量改进效果

#### Industry Context Integration

将 DefectDojo 的发现项与行业框架进行对比：

- **OWASP Top 10:** Web 应用安全风险
- **SANS Top 25:** 最危险的软件缺陷
- **CWE Top 25:** 最常见、影响最大的缺陷
- **Compliance frameworks:** SOC 2, ISO 27001, NIST CSF

## Troubleshooting MCP

### Diagnostic Checklist

在遇到连接问题时，请检查以下各项：

- ✅ Transport Type is **Streamable HTTP** (not SSE)
- ✅ MCP endpoint URL is correct: `https://[instance].defectdojo.com/mcp`
- ✅ Authorization header is enabled (toggle is ON)
- ✅ Token format includes `Token` prefix
- ✅ Token is valid and has appropriate permissions
- ✅ DefectDojo instance is accessible (can login via web UI)
- ✅ Network connectivity allows HTTPS connections

### Common Connection Issues

#### ❌ "Connection Error - Check if your MCP server is running"

**Cause:** 使用了已弃用的 SSE（Server-Sent Events）传输类型

**Solution:** 将传输类型更改为 `Streamable HTTP`

**Why:** DefectDojo MCP 服务器使用现代的 Streamable HTTP 协议，不再支持已弃用的 SSE。

---

#### ❌ "Authentication Failed" or "401 Unauthorized"

**Cause:** 身份验证请求头格式不正确或令牌无效

**Solutions:**

1. 确认请求头值使用 `Token` 前缀（而非 `Bearer`）
   ```
   ✅ Correct: Token 7c6cc2xxxxxxxxxxxxxxxxxxxx87fcf72ec2b3fb
   ❌ Wrong: Bearer 7c6cc2xxxxxxxxxxxxxxxxxxxx87fcf72ec2b3fb
   ```

2. 确保 Authorization 请求头开关已启用（处于开启状态）
3. 在 DefectDojo 中确认令牌仍然有效（Admin → API Tokens）
4. 检查令牌是否具有相应的读取权限

---

#### ❌ Tool Returns Empty Results

**Possible Causes:**

- 过滤条件过于严格（没有数据符合条件）
- DefectDojo 实例在所请求的类别中没有数据
- 令牌权限不足

**Solutions:**

1. 先尝试更宽泛的查询：`get_findings({ limit: 10 })`
2. 逐一移除过滤条件，找出限制过严的那个
3. 在 DefectDojo 中确认令牌权限
4. 直接在 DefectDojo 界面中检查数据是否存在

---

#### ⚠️ Slow Response Times

**Cause:** 一次性请求了过多数据

**Solutions:**

- 减小 `limit` 参数（从 50-100 开始）
- 使用更具体的过滤条件以缩小结果集
- 使用渐进式加载：先获取计数，再获取详情
- 对大型数据集实施分页

---
