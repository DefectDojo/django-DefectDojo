---
title: "MCP Server"
description: "DefectDojo's MCP Server allows you to use LLMs with DefectDojo Pro"
draft: false
audience: pro
weight: 23
aliases:
  - /en/ai/mcp_server_pro
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Note: AI features are a DefectDojo Pro-only feature.</span>

The DefectDojo Model Context Protocol (MCP) Server enables Large Language Models (LLMs) to intelligently interact with DefectDojo's vulnerability management data. Unlike traditional API integrations that simply transfer data, the MCP server provides structured context and semantic meaning that enables AI assistants to perform sophisticated security analysis and generate actionable insights.

> **Naming:** The UI labels these objects **Assets** and **Organizations**. The MCP tool names keep the original names — `get_products` returns Assets and `get_product_types` returns Organizations.

- **Structured Context:** MCP provides semantic meaning to DefectDojo data, not just raw data transfer
- **Pre-Processed Data:** DefectDojo's normalized, deduplicated data eliminates LLM preprocessing burden
- **Business Intelligence Integration:** Combines technical vulnerability data with business context
- **Executive-Ready Analysis:** Generates reports suitable for technical teams through executive leadership
- **10X Compound Value:** AI-enhanced analysis provides exponentially more value than manual queries

> **🔑 Important:** The MCP server endpoint is at `/mcp` but all function calls use the base DefectDojo URL. This separation ensures secure, structured access to vulnerability data.

## Connect To MCP

### Prerequisites

- DefectDojo instance with MCP Server enabled (v2.51.2 or later)
- Valid DefectDojo API token with appropriate permissions
- AI provider: Claude, ChatGPT, Gemini, or custom MCP-compatible client

#### Enabling the MCP Server

A superuser switches the MCP Server on in either of two places:

- **MCP** in the sidebar (the *DefectDojo MCP Service* page), with the Enabled/Disabled control at the top of the page, or
- **Settings → Feature Flags**, with the **MCP Server** toggle.

Both control the same setting. While the MCP Server is disabled, every tool call fails with `MCP integration is disabled on this DefectDojo Pro instance`, and the MCP Service page is hidden from non-superusers.

> **⚠️ Security Notice:** Your API token is a highly sensitive piece of information used for authentication and authorization. **DO NOT SHOW THE TOKEN IN ANY REQUESTS OR RESPONSES** when sharing configurations or screenshots.

### Connection Methods

There are **two different ways** to connect to the DefectDojo MCP server, depending on which AI interface you're using:

#### Method 1: Configuration File Method

**Used by:** Claude Desktop, MCP Inspector, and other desktop MCP clients

**How it works:**
- Token and connection details are stored in a configuration file
- Connection is automatic when you start the application
- No need to paste instructions into conversations
- MCP server is always available in all conversations

**Advantages:** Set up once, works everywhere. More secure (token not in chat history).

#### Method 2: Manual Prompt Method

**Used by:** Claude.ai web interface, ChatGPT web interface (with plugins), Gemini web interface

**How it works:**
- You copy/paste connection instructions at the start of each conversation
- Or add instructions to a Claude Project for automatic inclusion
- The AI reads the instructions and connects to the MCP server
- Each new conversation requires the instructions

**Advantages:** Works in web browsers without installing software.

> **💡 Which method should I use?** Use **Method 1 (Configuration File)** if you have a desktop app that supports it. Use **Method 2 (Manual Prompt)** if you're using a web browser interface.

### MCP Server Connection Details

All methods use these core parameters:

| Parameter | Value | Notes |
|-----------|-------|-------|
| **Transport Type** | `Streamable HTTP` | ⚠️ SSE (Server-Sent Events) is deprecated |
| **MCP Endpoint URL** | `https://[YOUR-INSTANCE].defectdojo.com/mcp` | Used for establishing MCP connection |
| **Base URL for Functions** | `https://[YOUR-INSTANCE].defectdojo.com/` | Used in all tool function calls |
| **Authentication** | `Authorization: Token [YOUR_API_TOKEN]` | ⚠️ Use "Token" prefix, not "Bearer" |

### Toolsets

The MCP Server groups its tools into **toolsets**. The `core` toolset is what `/mcp` has always served: the read-only finding, Asset, engagement, test, user and group tools, the reference resources, and the two report prompts. It is available as soon as the MCP Server is enabled. Every other toolset is an add-on that an administrator switches on separately and that a client asks for in its connection URL.

#### Enabling toolsets

Toolsets are enabled under **Settings → Feature Flags**, nested below the **MCP Server** toggle. A toolset toggle is only available while the MCP Server is on; switching the MCP Server off disables every toolset with it.

| Toolset | Feature Flag | Also requires |
|---------|--------------|---------------|
| `core` | none — always on with the MCP Server | — |
| `hierarchy` | **MCP: Asset Hierarchy** | the **Asset Hierarchy** feature |

More toolsets appear in the Feature Flags menu as they are released. A toolset's flag only controls what the MCP Server offers: it does not change the REST API, and every tool call still runs with the permissions of the API token that connects.

#### Selecting toolsets in the connection URL

Add a `toolsets` query parameter to the MCP endpoint URL. Names are comma-separated; `core` is always included, so it never needs to be listed.

| Endpoint URL | Tools offered |
|--------------|---------------|
| `https://[YOUR-INSTANCE].defectdojo.com/mcp` | `core` only. Unchanged from earlier releases. |
| `https://[YOUR-INSTANCE].defectdojo.com/mcp?toolsets=hierarchy` | `core` plus the Asset Hierarchy toolset. |
| `https://[YOUR-INSTANCE].defectdojo.com/mcp?toolsets=all` | `core` plus every toolset enabled on the instance. Requires the `Authorization` header to be sent when connecting, because the server reads the instance's Feature Flags with your token to resolve `all`. |

Any selection with a `toolsets` parameter also offers `get_instance_info`, a tool that reports the DefectDojo Pro version, which toolsets are enabled (`mcp_toolsets_enabled`), each Feature Flag's state, and whether the instance names its objects **Assets / Organizations** or **Products / Product Types**. Ask your assistant to call it when you are unsure which toolsets an instance provides.

The query string goes wherever your client takes the server URL — for the configuration-file clients in the guides below that is the URL argument, for example `"https://your-instance.defectdojo.com/mcp?toolsets=hierarchy"` in place of the plain `/mcp` URL. `mcp-remote`, Claude Code, Cursor, VS Code and other Streamable HTTP clients pass the query string through unchanged.

#### When a connection is refused

The MCP Server answers the connection request with a plain-text error instead of a session when it cannot serve the selection:

| Status | Meaning | What to do |
|--------|---------|------------|
| `400` | Unknown toolset name, an empty list, `all` mixed with names, or `toolsets` given twice. The body lists the valid names. | Fix the URL. |
| `401` | `toolsets=all` without an `Authorization` header. | Send the header, or list the toolsets explicitly. |
| `403` | `toolset '<name>' is not enabled on this DefectDojo Pro instance`. The toolset's Feature Flag is off. Checked when the connection carries an `Authorization` header; a connection without one is accepted and the same check runs on each tool call instead. | Ask an administrator to enable it under **Settings → Feature Flags**, or remove it from the URL. |
| `503` | The MCP Server could not read the instance's Feature Flags (DefectDojo unavailable or the token was rejected). It never silently falls back to `core`. | Check the instance and the token, then reconnect. |

If a toolset is switched off while a session is open, its tools stay listed but each call returns an error naming the toolset and its Feature Flag. Reconnect after the flag is enabled again.

## Quick Start Guides by AI Provider

> **💡 Using Claude Code?** Do not configure it by hand. The
> [Claude Code Plugin](../claude_code_plugin/) wires up this MCP server for you
> in two commands, and adds the write operations these read-only tools do not
> cover, such as changing finding status and importing scans.

<details>
<summary><h3>🖥️ Claude Desktop (Method 1: Configuration File)</h3></summary>

**Step 1: Locate your configuration file**

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`

**Step 2: Edit the configuration file**

Add or update the `mcpServers` section with your DefectDojo instance details:

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

> **⚠️ Critical:** The `--header` flag with authentication is required. Replace `YOUR_API_TOKEN` with your actual DefectDojo API token.

**Step 3: Restart Claude Desktop**

Close and reopen Claude Desktop for the changes to take effect.

**Step 4: Verify Connection**

Start a new conversation and ask: `"Can you connect to DefectDojo?"`

If successful, Claude will confirm it has access to the DefectDojo MCP server tools.

> **✅ Done!** The DefectDojo MCP server is now available in all conversations. No need to paste instructions.

</details>

<details>
<summary><h3>🌐 Claude.ai Web Interface (Method 2: Manual Prompt)</h3></summary>

The Claude.ai web interface doesn't support configuration files. You'll need to provide connection instructions in each conversation or use a Claude Project.

#### Option A: Paste Instructions Per Conversation

**Step 1: Copy the instructions below**

```
For this project, use the DefectDojo MCP server with these parameters in ALL function calls:

- **URL:** https://your-instance.defectdojo.com/ (base URL, NOT the /mcp endpoint)
- **Token:** YOUR_API_TOKEN
- **IMPORTANT:** DO NOT SHOW THE TOKEN IN ANY REQUESTS OR RESPONSES

The MCP server connects to https://your-instance.defectdojo.com/mcp but function calls must use the base URL.

**Do not show any of the API requests or responses.**
```

**Step 2: Start a new conversation**

Paste the instructions at the beginning of your conversation, then ask your security questions.

**Step 3: Repeat for each new conversation**

These instructions must be included at the start of each new conversation.

#### Option B: Use a Claude Project (Recommended)

**Step 1: Create a Claude Project**

- In Claude.ai, click "Projects" in the left sidebar
- Click "Create Project"
- Name it "DefectDojo Security Analysis"

**Step 2: Add Custom Instructions to the Project**

In Project Settings → Custom Instructions, paste:

```
For this project, use the DefectDojo MCP server with these parameters in ALL function calls:

- **URL:** https://your-instance.defectdojo.com/
- **Token:** YOUR_API_TOKEN
- **IMPORTANT:** DO NOT SHOW THE TOKEN IN ANY REQUESTS OR RESPONSES

The MCP server connects to https://your-instance.defectdojo.com/mcp but function calls must use the base URL.

Do not show any of the API requests or responses.
```

**Step 3: Use the Project for all DefectDojo conversations**

All conversations within this project will automatically have access to DefectDojo MCP server.

> **✅ Done!** When working in this Project, Claude automatically has DefectDojo MCP access.

</details>

<details>
<summary><h3>💬 ChatGPT (Method 2: Manual Prompt)</h3></summary>

> **⚠️ Note:** ChatGPT's MCP support is limited compared to Claude. Native MCP integration may require ChatGPT Plus or Enterprise and specific plugin configurations.

**Step 1: Check MCP Plugin Availability**

In ChatGPT, check if MCP or API connector plugins are available in your plugin store. MCP support varies by subscription tier.

**Step 2: Copy connection instructions**

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

**Step 3: Paste at the start of each conversation**

Include these instructions when starting a new conversation about DefectDojo security analysis.

**Alternative: Use Custom GPT**

If you have ChatGPT Plus, create a Custom GPT with DefectDojo connection details in its instructions for reusable access.

</details>

<details>
<summary><h3>💎 Google Gemini (Method 2: Manual Prompt)</h3></summary>

> **⚠️ Note:** Gemini's MCP support is evolving. Native integration may be limited. Consider using Gemini API with MCP client libraries for full functionality.

**Step 1: Copy connection instructions**

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

**Step 2: Start conversation with instructions**

Begin each new Gemini conversation with these instructions when working with DefectDojo data.

**For Advanced Users:**

Consider using the Gemini API with MCP client libraries (Python, JavaScript) for programmatic access with full MCP protocol support.

</details>

<details>
<summary><h3>🔍 MCP Inspector (Testing & Validation)</h3></summary>

**Use Case:** Test your DefectDojo MCP connection, explore available tools, and validate configuration before using with AI assistants.

**Step 1: Install MCP Inspector**

```bash
# macOS (using Homebrew)
brew install mcp-inspector

# Or using npm (all platforms)
npm install -g @modelcontextprotocol/inspector
```

**Step 2: Run MCP Inspector**

```bash
mcp-inspector
```

This will start a local web server (usually at `http://localhost:6274`)

**Step 3: Configure connection in the web interface**

- **Transport Type:** `Streamable HTTP`
- **URL:** `https://your-instance.defectdojo.com/mcp`
- **Connection Type:** `Via Proxy`
- **Custom Headers:**
  - Name: `Authorization`
  - Value: `Token YOUR_API_TOKEN`
  - **Important:** Enable the toggle switch next to the header

**Step 4: Click "Connect"**

Once connected, you can explore:

- **Tools tab:** View all 18 `core` tools and their parameters (19 when the URL carries a `toolsets` parameter, plus any add-on toolsets you selected)
- **Prompts tab:** See the 2 pre-configured prompt templates
- **Resources tab:** Check the 6 reference data resources

> **✅ Perfect for:** Verifying your configuration works before setting up AI assistants, exploring tool capabilities, and troubleshooting connection issues.

</details>

---

> **✅ Connection Successful?** Once connected via any method, test by asking your AI assistant: `"How many active findings do we have in DefectDojo?"`

---

## Available Tools Reference

The `core` toolset of the DefectDojo MCP Server provides 18 tools for accessing and analyzing vulnerability data, 6 reference resources, and 2 pre-configured prompts. Each tool includes intelligent parameter handling and returns structured data optimized for LLM analysis. Connections that select toolsets in the URL (see [Toolsets](#toolsets)) also receive `get_instance_info`, and add-on toolsets contribute their own tools on top of the ones listed here.

> **💡 Parameter Note:** All tools accept an optional `token` parameter. If not provided in individual calls, the LLM will use the token from the connection configuration.

> **💡 Pagination Note:** Every list tool accepts `limit` (1–1000, default 100) and `offset` (minimum 0, default 0). Every `*_by_id` tool takes a single required numeric ID (minimum 1).

---

### 🔍 Findings Analysis Tools

<details>
<summary><h4>get_findings</h4></summary>

**Description:** Retrieve findings from DefectDojo with sophisticated filtering capabilities. This is the most powerful and frequently used tool for vulnerability analysis.

**Parameters:**

**severity** (Optional)
- **Type:** Array of strings
- **Values:** `Critical`, `High`, `Medium`, `Low`, `Info`
- **Example:** `["Critical", "High"]`
- **Usage:** Filter findings by severity level. Multiple values can be provided for compound queries.

**status** (Optional)
- **Type:** Array of strings
- **Values:** `Any`, `Active`, `Open`, `Verified`, `Out of Scope`, `False Positive`, `Inactive`, `Risk Accepted`, `Closed`, `Under Review`
- **Example:** `["Active", "Verified"]`
- **Usage:** Filter findings by their current status. Use `Active` for current risk assessment.

**date** (Optional)
- **Type:** Array with single string value
- **Values:** `0 - Any date`, `1 - Today`, `2 - Past 7 days`, `3 - Past 30 days`, `4 - Past 90 days`, `5 - Current month`, `6 - Current year`, `7 - Past year`
- **Example:** `["3 - Past 30 days"]`
- **Usage:** Filter findings by discovery date. Only one value allowed.

**tags** (Optional)
- **Type:** Array of strings
- **Example:** `["production", "external"]`
- **Usage:** Match findings that carry **any** of these exact tags (OR). Combine with the other filters to narrow further.

**tags__and** (Optional)
- **Type:** Array of strings
- **Example:** `["production", "pci"]`
- **Usage:** Match findings that carry **all** of these exact tags (AND).

**not_tags** (Optional)
- **Type:** Array of strings
- **Example:** `["wontfix"]`
- **Usage:** Exclude findings that carry **any** of these exact tags.

**limit** (Optional)
- **Type:** Number
- **Default:** 100
- **Range:** 1-100
- **Usage:** Number of findings to return. For counts only, set to 1 and use the count property in response.

**offset** (Optional)
- **Type:** Number
- **Default:** 0
- **Usage:** Pagination offset for retrieving additional results.

> **💡 Best Practice:** For risk assessment queries, always use `status: ["Active"]` to focus on current, unresolved vulnerabilities rather than historical data.

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

**User asks:** "Show me active findings tagged both `production` and `pci`"

**LLM calls:**
```
get_findings({
  status: ["Active"],
  tags__and: ["production", "pci"]
})
```

</details>

<details>
<summary><h4>get_finding_by_id</h4></summary>

**Description:** Retrieve detailed information about a specific finding using its unique identifier.

**Parameters:**

**finding_id** (Required)
- **Type:** Number
- **Minimum:** 1
- **Usage:** The unique ID of the finding to retrieve.

**Example Query:**

**User asks:** "Get details for finding #1234"

**LLM calls:** `get_finding_by_id({ finding_id: 1234 })`

</details>

<details>
<summary><h4>finding_summary</h4></summary>

**Description:** Retrieve aggregate finding metrics in a single call, rather than fetching findings and counting them. Returns counts by severity, average priority and risk score, average finding age, and the most common CWEs.

> **Note on counts:** The `active_*` counts cover every active finding, whether or not it has
> been verified. Verified findings are reported separately as `verified_findings` and
> `active_verified_findings`, so one call gives you both views. The **Enforce Verified Status**
> system settings do not narrow these counts.

**Parameters:**

**product_id** (Optional)
- **Type:** Number
- **Minimum:** 1
- **Usage:** Scope the summary to a single product.

**engagement_id** (Optional)
- **Type:** Number
- **Minimum:** 1
- **Usage:** Scope the summary to a single engagement.

**date** (Optional)
- **Type:** Array with single string value
- **Values:** `0 - Any date`, `1 - Today`, `2 - Past 7 days`, `3 - Past 30 days`, `4 - Past 90 days`, `5 - Current month`, `6 - Current year`, `7 - Past year`
- **Example:** `["3 - Past 30 days"]`
- **Usage:** Restrict the summary to findings discovered in the period.

**tags** (Optional)
- **Type:** Array of strings
- **Example:** `["production", "external"]`
- **Usage:** Restrict the summary to findings that carry **any** of these exact tags (OR).

**tags__and** (Optional)
- **Type:** Array of strings
- **Example:** `["production", "pci"]`
- **Usage:** Restrict the summary to findings that carry **all** of these exact tags (AND).

**not_tags** (Optional)
- **Type:** Array of strings
- **Example:** `["wontfix"]`
- **Usage:** Exclude findings that carry **any** of these exact tags from the summary.

> **ℹ️ Scope required:** Provide at least one scoping filter: `product_id`, `engagement_id`, `date`, `tags`, or `tags__and`. `not_tags` only refines an existing scope.

> **💡 Best Practice:** Use this instead of `get_findings` whenever the question is "how many" or "what is the spread". One summary call replaces paging through findings and counting them, and the counts stay correct beyond the 100-record page limit.

**Example Query:**

**User asks:** "Give me a severity breakdown for the payments product over the last quarter"

**LLM calls:**
```
finding_summary({
  product_id: 42,
  date: ["4 - Past 90 days"]
})
```

**User asks:** "What's the severity spread for everything tagged `internet-facing`?"

**LLM calls:**
```
finding_summary({
  tags: ["internet-facing"]
})
```

</details>

<details>
<summary><h4>risk_summary</h4></summary>

**Description:** Retrieve the aggregate risk posture for a single product, including average priority, risk score, active finding counts, and business criticality.

> **Note on counts:** The `active_*` counts cover every active finding, whether or not it has
> been verified. Verified findings are reported separately as `verified_findings` and
> `active_verified_findings`, so one call gives you both views. The **Enforce Verified Status**
> system settings do not narrow these counts.

**Parameters:**

**product_id** (Required)
- **Type:** Number
- **Minimum:** 1
- **Usage:** The product to summarize.

**Example Query:**

**User asks:** "How risky is the payments API right now?"

**LLM calls:** `risk_summary({ product_id: 42 })`

</details>

---

### 📦 Asset & Engagement Tools

<details>
<summary><h4>get_products</h4></summary>

**Description:** Retrieve all Assets from DefectDojo. Assets represent applications, services, or systems being tested.

**Parameters:**

**limit** (Optional)
- **Default:** 100
- **Usage:** Maximum number of Assets to return.

**offset** (Optional)
- **Default:** 0
- **Usage:** Pagination offset.

**name** (Optional)
- **Type:** String
- **Usage:** Filter Assets by name.

**business_criticality** (Optional)
- **Type:** Array
- **Values:** `Very High`, `High`, `Medium`, `Low`, `Very Low`

**platform** (Optional)
- **Type:** Array
- **Values:** `API`, `Desktop`, `Internet of Things`, `Mobile`, `Web`

**lifecycle** (Optional)
- **Type:** Array
- **Values:** `Construction`, `Production`, `Retirement`

**external_audience** (Optional)
- **Type:** Boolean string (`true` / `false`)

**internet_accessible** (Optional)
- **Type:** Boolean string (`true` / `false`)

</details>

<details>
<summary><h4>get_product_by_id</h4></summary>

**Description:** Retrieve one Asset by its ID, including its `prod_type` (the owning Organization). Use it to resolve the Asset that owns an engagement without paging through `get_products`.

**Parameters:**

**product_id** (Required)
- **Type:** Number
- **Minimum:** 1

</details>

<details>
<summary><h4>get_product_types</h4></summary>

**Description:** Retrieve Organizations from DefectDojo. Organizations help organize Assets into logical groupings.

**Parameters:** `limit` and `offset` only.

</details>

<details>
<summary><h4>get_product_type_by_id</h4></summary>

**Description:** Retrieve one Organization by its ID.

**Parameters:**

**product_type_id** (Required)
- **Type:** Number
- **Minimum:** 1

</details>

<details>
<summary><h4>get_engagements</h4></summary>

**Description:** Retrieve security testing engagements. Engagements represent specific testing activities or time periods for an Asset.

**Parameters:**

**limit** / **offset** (Optional) — as for `get_products`.

**product_id** (Optional)
- **Type:** Number
- **Minimum:** 1
- **Usage:** Only return engagements belonging to this Asset.

</details>

<details>
<summary><h4>get_engagement_by_id</h4></summary>

**Description:** Retrieve one engagement by its ID. The response's `product` field is the owning Asset, so a finding's `engagement_id` can be walked up to its Asset with one call.

**Parameters:**

**engagement_id** (Required)
- **Type:** Number
- **Minimum:** 1

</details>

<details>
<summary><h4>get_tests</h4></summary>

**Description:** Retrieve security tests from DefectDojo. Tests contain scan results from specific security tools or manual testing.

**Parameters:**

**limit** / **offset** (Optional) — as for `get_products`.

**engagement_id** (Optional)
- **Type:** Number
- **Minimum:** 1
- **Usage:** Only return tests belonging to this engagement.

</details>

<details>
<summary><h4>get_test_by_id</h4></summary>

**Description:** Retrieve one test by its ID. The response's `engagement` field is the owning engagement.

**Parameters:**

**test_id** (Required)
- **Type:** Number
- **Minimum:** 1

</details>

> **💡 Walking the object graph:** Finding → `get_test_by_id` → `get_engagement_by_id` → `get_product_by_id` → `get_product_type_by_id` resolves a finding's owning test, engagement, Asset and Organization with four direct calls instead of paging the list tools.

---

### 👥 User & Access Management Tools

<details>
<summary><h4>get_users</h4></summary>

**Description:** Retrieve all users from DefectDojo for stakeholder analysis and accountability mapping.

**Parameters:**

**limit** (Optional)
- **Default:** 100

**offset** (Optional)
- **Default:** 0

**username** (Optional)
- **Type:** String

**email** (Optional)
- **Type:** String

**is_active** (Optional)
- **Type:** Boolean string (`true` / `false`)

**is_superuser** (Optional)
- **Type:** Boolean string (`true` / `false`)

</details>

<details>
<summary><h4>get_user_by_id</h4></summary>

**Description:** Retrieve detailed information about a specific user.

**Parameters:**

**user_id** (Required)
- **Type:** Number
- **Minimum:** 1

</details>

<details>
<summary><h4>get_groups</h4></summary>

**Description:** Retrieve user groups for organizational structure analysis and permission mapping.

**Parameters:**

**limit** / **offset** (Optional) — as for `get_users`.

**name** (Optional)
- **Type:** String
- **Usage:** Filter groups by name.

</details>

<details>
<summary><h4>get_group_by_id</h4></summary>

**Description:** Retrieve detailed information about a specific group.

**Parameters:**

**group_id** (Required)
- **Type:** Number
- **Minimum:** 1

</details>

<details>
<summary><h4>get_dojo_group_members</h4></summary>

**Description:** Retrieve group memberships for team analysis. Filter by group to list a group's members, by user to list the groups a user belongs to, or leave both out to page through every membership.

**Parameters:**

**group_id** (Optional)
- **Type:** Number
- **Minimum:** 1
- **Usage:** Only return memberships of this group.

**user_id** (Optional)
- **Type:** Number
- **Minimum:** 1
- **Usage:** Only return memberships of this user.

**limit** (Optional)
- **Default:** 100

**offset** (Optional)
- **Default:** 0

</details>

<details>
<summary><h4>get_roles</h4></summary>

**Description:** Retrieve role definitions from DefectDojo for understanding permission structures.

**Parameters:** `limit` and `offset` only.

</details>

---

## Reference Resources

The `core` toolset publishes 6 read-only JSON resources (MIME type `application/json`). They are reference material bundled with the MCP Server, not data from your DefectDojo instance, and are available without any tool call so an assistant can map findings to a standard or explain a regulatory obligation while it reports.

| Resource | URI | Contents |
|----------|-----|----------|
| `eu-cyber-resilience-act` | `mcp://resource/eu_cyber_resilience_act.json` | EU Cyber Resilience Act (CRA) |
| `owasp-top-10-2025` | `mcp://resource/owasp_top_10_2025.json` | OWASP Top 10 (2025) |
| `cwe-to-owasp-top-10-2025` | `mcp://resource/cwe_to_owasp_2025_mapping.json` | Mapping of CWE to OWASP Top 10 (2025) |
| `owasp-agentic-top-10-2026` | `mcp://resource/owasp_agentic_top_10_2026.json` | OWASP Agentic Top 10 (2026) |
| `owasp-top-10-2021` | `mcp://resource/owasp_top_10_2021.json` | OWASP Top 10 (2021) |
| `cwe-to-owasp-top-10-2021` | `mcp://resource/cwe_to_owasp_2021_mapping.json` | Mapping of CWE to OWASP Top 10 (2021) |

Ask your assistant to read a resource by URI (for example, "read `mcp://resource/cwe_to_owasp_2025_mapping.json` and group our open findings by OWASP category") when a report should cite a standard.

---

## Pre-Configured Prompts

The DefectDojo MCP Server includes pre-configured prompts that demonstrate best practices for common analysis scenarios. These prompts can be invoked directly by your AI assistant.

### 🛡️ SAST Review Report

**Purpose:** Create a comprehensive report evaluating the effectiveness of SAST (Static Application Security Testing) tools based on DefectDojo data.

**Generated Analysis Includes:**

- False positive rates by tool and vulnerability type
- Mean time to remediation by severity level
- Critical vulnerabilities appearing multiple times (deduplication gaps)
- Developer team performance comparison
- Recommendations for tool configuration improvements
- Training gaps identified from recurring vulnerability patterns
- Cost analysis of current vs. recommended tooling approach

**Output Format:** Technical assessment report in HTML, suitable for justifying security tooling budget requests.

### 📊 Security Landscape Report

**Purpose:** Create a dashboard-style report providing an overview of the security landscape based on DefectDojo data, suitable for quarterly board meetings.

**Generated Analysis Includes:**

- Vulnerability trends over past 90 days
- Development teams with highest critical/high severity findings
- Risk exposure by Asset and Organization
- Top 5 CWE categories requiring immediate attention
- Specific remediation actions with cost-benefit analysis
- 6-month roadmap for improving security posture

**Output Format:** Executive-level HTML report with visual elements, statistics cards, and business risk focus.

> **💡 Using Prompts:** To invoke a prompt, simply ask your AI assistant: "Create a SAST Review Report" or "Generate a Security Landscape Report using DefectDojo data"

---

## Use Case Examples

### Use Case 1: Executive Security Dashboard

**Scenario:** CISO needs quarterly security metrics for board presentation

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

1. `get_findings` - Get total active finding counts
2. `get_findings` - Critical and High severity analysis
3. `get_findings` - 90-day trending data
4. `get_products` - Asset vulnerability distribution
5. `get_engagements` - Recent testing activities

**Generated Output:** Executive-level HTML report with vulnerability trends, risk exposure by Asset, top CWE categories, specific remediation actions with ROI, and 6-month security roadmap.

---

### Use Case 2: Developer Team Performance Analysis

**Scenario:** Engineering manager wants to understand which teams need additional security training

**User Prompt:**

```
"Which development teams have the most security findings? What types of vulnerabilities 
are they creating repeatedly? Based on this analysis, recommend specific security 
training programs for each team."
```

**What happens behind the scenes:**

1. `get_findings` - All active findings
2. `get_products` - Link findings to Assets/teams
3. `get_groups` - Team organization structure
4. `get_users` - Individual developer accountability

**Analysis Delivered:** Findings grouped by team, CWE pattern analysis showing repeated mistakes, training gap identification, and recommendations for targeted security training programs.

---

### Use Case 3: Tool Effectiveness Assessment

**Scenario:** Security team evaluating ROI of current SAST tools

**User Prompt:**

```
"Analyze the effectiveness of our SAST tools. Show me false positive rates, 
mean time to remediation, which tools find the most valuable vulnerabilities, 
and recommend configuration improvements or alternative tools."
```

**What happens behind the scenes:**

1. `get_tests` - All security tests by tool
2. `get_findings` - False positive analysis
3. `get_findings` - Active findings by tool
4. `get_findings` - Closed findings for remediation patterns

**Analysis Delivered:** False positive rates by tool, mean time to remediation by severity, duplicate finding analysis, tool configuration recommendations, training gaps, and cost-benefit analysis of alternative tooling approaches.

---

### Use Case 4: Compliance Reporting

**Scenario:** Preparing for SOC 2 audit requiring vulnerability management evidence

**User Prompt:**

```
"Generate a SOC 2 compliance report showing our vulnerability management processes, 
including discovery and remediation procedures, SLA compliance, continuous monitoring 
evidence, and accountability documentation."
```

**What happens behind the scenes:**

1. `get_findings` - Critical/High active findings
2. `get_findings` - Year-to-date discovery trends
3. `get_engagements` - Testing frequency and coverage
4. `get_users` - Remediation accountability

**Analysis Delivered:** Vulnerability discovery and remediation processes, SLA compliance tracking, evidence of continuous monitoring, accountability documentation, and gaps requiring remediation before audit.

---

### Use Case 5: Risk Prioritization

**Scenario:** Security team has limited resources and needs to prioritize remediation efforts

**User Prompt:**

```
"What are the highest priority vulnerabilities we should fix first? Consider severity, 
how long they've been open, exploitability, and business impact. Give me a prioritized 
remediation roadmap with effort estimates."
```

**What happens behind the scenes:**

1. `get_findings` - Critical/High active findings
2. `get_products` - Business criticality context
3. Analyze aging metrics (days since discovery)
4. Cross-reference with EPSS scores (exploit prediction)

**Analysis Delivered:** Risk-ranked vulnerability list combining severity, age, exploitability, and business impact. Specific remediation roadmap with effort estimates and expected risk reduction.

---


## Best Practices & Query Patterns

### Progressive Data Loading Strategy

Your AI assistant optimizes performance by following these data loading patterns automatically:

**1. Start with Summary Data**

Ask for counts before requesting detailed analysis:

```
"How many critical and high severity findings do we have?"
```

Your AI assistant will use the `get_findings` tool with `limit: 1` to efficiently retrieve just the count.

**2. Use Strategic Pagination**

For large datasets, your AI assistant automatically pages through results:

```
"Analyze all our active vulnerabilities"
```

The AI will make multiple calls if needed, starting with reasonable limits and increasing as required.

**3. Efficient Data Reuse**

Ask related questions in sequence to avoid redundant queries:

```
"Show me all critical findings, then tell me which CWE categories they fall into"
```

The AI will reuse the findings data from the first query for the CWE analysis.

### Smart Filtering Strategies

Craft your prompts to leverage DefectDojo's powerful filtering capabilities:

#### Severity-Based Queries

**User Prompt:**
```
"Show me all Critical and High severity issues that need immediate attention"
```

**Behind the scenes:** AI uses `get_findings` with severity and status filters

#### Time-Based Queries

**User Prompt:**
```
"What new vulnerabilities have been discovered in the past 30 days?"
```

**Behind the scenes:** AI applies date filter for "Past 30 days" with active status

#### Combined Filtering

**User Prompt:**
```
"Give me a risk assessment of all critical and high active findings from the past 90 days"
```

**Behind the scenes:** AI combines severity, status, and date filters for comprehensive analysis

### Cross-Reference Analysis

Your AI assistant automatically links findings to organizational context. Simply ask comprehensive questions:

**User Prompt:**
```
"Which products have the most critical vulnerabilities and who is responsible for fixing them?"
```

**Behind the scenes:** AI links findings → tests → engagements → Assets → users/groups for complete context

### Vulnerability Intelligence Analysis

**CWE Pattern Analysis**

**User Prompt:**
```
"What are the most common vulnerability types in our codebase and which teams are creating them?"
```

AI will group findings by CWE to identify recurring patterns, training needs, and architectural issues.

**Aging Metrics**

**User Prompt:**
```
"How long have our critical vulnerabilities been open? Which ones are overdue for remediation?"
```

AI calculates time since discovery and flags findings exceeding SLA thresholds.

**Vulnerability Density**

**User Prompt:**
```
"Which products have the highest vulnerability density and represent the greatest risk?"
```

AI calculates findings per Asset and generates risk scores combining severity and volume.

### Report Enhancement Standards

#### Always Include

- **Specific metrics:** Actual counts by severity, not generalizations
- **CWE analysis:** Top vulnerability types with descriptions
- **Aging data:** How long vulnerabilities have been open
- **Actionable recommendations:** What to do next with timelines
- **ROI calculations:** Expected cost vs. benefit of actions
- **Success metrics:** How to measure improvement

#### Industry Context Integration

Compare DefectDojo findings against industry frameworks:

- **OWASP Top 10:** Web application security risks
- **SANS Top 25:** Most dangerous software weaknesses
- **CWE Top 25:** Most common and impactful weaknesses
- **Compliance frameworks:** SOC 2, ISO 27001, NIST CSF

## Troubleshooting MCP

### Diagnostic Checklist

Verify these items when experiencing connection issues:

- ✅ Transport Type is **Streamable HTTP** (not SSE)
- ✅ MCP endpoint URL is correct: `https://[instance].defectdojo.com/mcp`
- ✅ Authorization header is enabled (toggle is ON)
- ✅ Token format includes `Token` prefix
- ✅ Token is valid and has appropriate permissions
- ✅ DefectDojo instance is accessible (can login via web UI)
- ✅ Network connectivity allows HTTPS connections

### Common Connection Issues

#### ❌ "Connection Error - Check if your MCP server is running"

**Cause:** Using deprecated SSE (Server-Sent Events) transport type

**Solution:** Change Transport Type to `Streamable HTTP`

**Why:** DefectDojo MCP Server uses modern Streamable HTTP protocol. SSE is deprecated and not supported.

---

#### ❌ "Authentication Failed" or "401 Unauthorized"

**Cause:** Incorrect authentication header format or invalid token

**Solutions:**

1. Verify header value uses `Token` prefix (not `Bearer`)
   ```
   ✅ Correct: Token 7c6cc2xxxxxxxxxxxxxxxxxxxx87fcf72ec2b3fb
   ❌ Wrong: Bearer 7c6cc2xxxxxxxxxxxxxxxxxxxx87fcf72ec2b3fb
   ```

2. Ensure Authorization header toggle is ENABLED (turned ON)
3. Verify token is still valid in DefectDojo (Admin → API Tokens)
4. Check token has appropriate permissions for read access

---

#### ❌ "toolset 'hierarchy' is not enabled on this DefectDojo Pro instance"

**Cause:** The connection URL asks for a toolset whose Feature Flag is off, or the MCP Server itself is disabled.

**Solutions:**

1. Ask a superuser to open **Settings → Feature Flags**, confirm **MCP Server** is on, and enable the toolset's flag (for `hierarchy`, **MCP: Asset Hierarchy**, which also needs the **Asset Hierarchy** feature)
2. Or remove the toolset from the `toolsets` parameter and reconnect
3. Ask your assistant to call `get_instance_info` to see which toolsets the instance has enabled

---

#### ❌ Tool Returns Empty Results

**Possible Causes:**

- Filters are too restrictive (no data matches criteria)
- DefectDojo instance has no data in requested category
- Insufficient token permissions

**Solutions:**

1. Try broader query first: `get_findings({ limit: 10 })`
2. Remove filters one at a time to identify the restrictive filter
3. Verify token permissions in DefectDojo
4. Check if data exists directly in DefectDojo UI

---

#### ⚠️ Slow Response Times

**Cause:** Requesting too much data at once

**Solutions:**

- Reduce `limit` parameter (start with 50-100)
- Use more specific filters to reduce result set size
- Use progressive loading: get counts first, then details
- Implement pagination for large datasets

---