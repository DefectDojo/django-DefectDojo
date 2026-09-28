---
title: "Nightfall AI"
description: "How to set up the Nightfall AI Upstream Connector for DefectDojo"
weight: 94
audience: pro
---
The Nightfall AI connector imports **data loss prevention (DLP) violations** — sensitive data Nightfall has detected across your connected SaaS tools. DefectDojo creates a Record for each **connected integration** that has violations.

The integration is the natural grouping here, because Nightfall's asset is the data source itself: Slack, Google Drive, GitHub, Jira, Confluence, Salesforce, Zendesk, Notion, Teams, OneDrive, the browser extension, and inline email.

#### Prerequisites

A Nightfall **API key**, sent as a bearer token and never logged.

#### Connector Mappings

1. Enter `https://api.nightfall.ai/dlp/v1` in the **Location** field.
2. Enter your Nightfall API key in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each integration with violations becomes a Record. Integrations with no violations are not mapped.
