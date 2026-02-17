---
title: "MCP Server (Pro)"
description: "DefectDojo's MCP Server allows you to use LLMs with DefectDojo Pro"
draft: false
weight: 2
aliases:
  - /en/ai/mcp_server_pro
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: AI features are a DefectDojo Pro-only feature.</span>

The DefectDojo Model Context Protocol (MCP) Server enables Large Language Models (LLMs) to intelligently interact with DefectDojo's vulnerability management data. Unlike traditional API integrations that simply transfer data, the MCP server provides structured context and semantic meaning that enables AI assistants to perform sophisticated security analysis and generate actionable insights.

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

## Quick Start Guides by AI Provider

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

- **Tools tab:** View all 12 available tools and their parameters
- **Prompts tab:** See pre-configured prompt templates
- **Resources tab:** Check available data resources

> **✅ Perfect for:** Verifying your configuration works before setting up AI assistants, exploring tool capabilities, and troubleshooting connection issues.

</details>

---

> **✅ Connection Successful?** Once connected via any method, test by asking your AI assistant: `"How many active findings do we have in DefectDojo?"`

---

## Available Tools Reference

The DefectDojo MCP Server provides 12 tools for accessing and analyzing vulnerability data. Each tool includes intelligent parameter handling and returns structured data optimized for LLM analysis.

> **💡 Parameter Note:** All tools accept an optional `token` parameter. If not provided in individual calls, the LLM will use the token from the connection configuration.

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

---

### 📦 Product & Engagement Tools

<details>
<summary><h4>get_products</h4></summary>

**Description:** Retrieve all products from DefectDojo. Products represent applications, services, or systems being tested.

**Parameters:**

**limit** (Optional)
- **Default:** 100
- **Usage:** Maximum number of products to return.

**offset** (Optional)
- **Default:** 0
- **Usage:** Pagination offset.

</details>

<details>
<summary><h4>get_product_types</h4></summary>

**Description:** Retrieve product type categories from DefectDojo. Product types help organize products into logical groupings.

**Parameters:** Same as `get_products`

</details>

<details>
<summary><h4>get_engagements</h4></summary>

**Description:** Retrieve security testing engagements. Engagements represent specific testing activities or time periods for a product.

**Parameters:** Same as `get_products`

</details>

<details>
<summary><h4>get_tests</h4></summary>

**Description:** Retrieve security tests from DefectDojo. Tests contain scan results from specific security tools or manual testing.

**Parameters:** Same as `get_products`

</details>

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

**Parameters:** Same as `get_users`

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

**Description:** Retrieve all members of a specific group for team analysis.

**Parameters:**

**group_id** (Required)
- **Type:** Number
- **Minimum:** 1

**limit** (Optional)
- **Default:** 100

**offset** (Optional)
- **Default:** 0

</details>

<details>
<summary><h4>get_roles</h4></summary>

**Description:** Retrieve role definitions from DefectDojo for understanding permission structures.

**Parameters:** Same as `get_users`

</details>

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
- Risk exposure by product and product type
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
4. `get_products` - Product vulnerability distribution
5. `get_engagements` - Recent testing activities

**Generated Output:** Executive-level HTML report with vulnerability trends, risk exposure by product, top CWE categories, specific remediation actions with ROI, and 6-month security roadmap.

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
2. `get_products` - Link findings to products/teams
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

**Behind the scenes:** AI links findings → tests → engagements → products → users/groups for complete context

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

AI calculates findings per product and generates risk scores combining severity and volume.

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