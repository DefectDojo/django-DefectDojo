---
title: "Group-IB ASM"
description: "How to set up the Group-IB ASM Upstream Connector for DefectDojo"
weight: 68
audience: pro
---
The Group-IB ASM (Attack Surface Management) connector uses the Group-IB ASM REST API to pull external attack-surface **issues** (findings) into DefectDojo. DefectDojo discovers each Group-IB **company/tenant** as a separate Record and imports that company's issues on a scheduled, incremental basis. The asset each issue relates to (a domain, IP, or URL) is attached to the resulting finding as an **Endpoint**.

#### Prerequisites

You will need your Group-IB ASM login and an API key. We recommend creating a dedicated service account for DefectDojo so that automated activity can be distinguished from manual team actions.

To generate an API key:

1. Open Group-IB Attack Surface Management, click **Help** in the lower-left corner, and select **API**.
2. Click **Generate API Key** (top-right, under your username).
3. Enter your SSO password and click **Next**, then click **Copy token**.
4. Store the key in a secret manager and plan for regular rotation.

#### Connector Mappings

Group-IB ASM authenticates with HTTP Basic Auth, where the username is your ASM login and the password is your API key. **Both values are required** — the API key alone is not sufficient.

1. Enter `https://asm.group-ib.com` in the **Location** field. This is the same for all Group-IB ASM tenants.
2. Enter your ASM login (usually an email address) in the **Username** field.
3. Enter your API key in the **API Key** (Secret) field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported. Findings below the selected severity are not imported.

DefectDojo maps each Group-IB **company** as a separate Record, using the company ID as the identifier. On the first Sync, DefectDojo backfills recent issue history; subsequent Syncs are incremental, pulling only issues changed since the last Sync (tracked by each issue's most recent `lastSeen` timestamp).

#### Scoping to a single company (optional)

By default, the connector automatically discovers the companies available to your API credentials (via the ASM `clients` endpoint) and creates one Record per company. This is the recommended setup and requires no extra configuration.

If the `clients` endpoint is not available for your tenant — for example, when it is restricted to partner/MSP accounts — the connector can be scoped to one company by supplying its **company ID** as a `company_id` tool-specific field on the connector configuration. When `company_id` is set, DefectDojo uses that company directly instead of enumerating companies. Leave it unset to use automatic discovery.

See the Group-IB ASM REST API manual (available in-product via **Help → API**) for more information.
