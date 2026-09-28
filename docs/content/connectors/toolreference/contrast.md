---
title: "Contrast"
description: "How to set up the Contrast Upstream Connector for DefectDojo"
weight: 39
audience: pro
---
The Contrast connector uses the Contrast Assess REST API to import application vulnerabilities. DefectDojo discovers the applications in your Contrast organization and creates a Record for each one.

#### Prerequisites

You will need four values from Contrast. We recommend creating a dedicated service account so automated activity is easy to distinguish from your team's manual actions. In the Contrast UI, under **User Settings > Profile > Your Keys**, you can find:

* Your organization **API Key**.
* Your personal **Service Key**.
* The **username** the credentials belong to (the account's login email).
* Your **Organization ID** — the UUID of the organization to import from, also shown under **Organization Settings**.

#### Connector Mappings

1. Enter the base URL you use to access Contrast in the **Location** field — for the hosted product this is typically `https://app.contrastsecurity.com` (or your regional / self-hosted Team Server URL).
2. Enter the account login email in the **Username** field.
3. Enter the organization **API Key** in the **API Key** field.
4. Enter the personal **Service Key** in the **Service Key** field.
5. Enter the **Organization ID** (UUID) in the **Organization ID** field.
6. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each Contrast application becomes a Record, and its vulnerabilities are imported as findings.
