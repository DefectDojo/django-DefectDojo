---
title: "Akto"
description: "How to set up the Akto Upstream Connector for DefectDojo"
weight: 14
audience: pro
---
The Akto connector imports **API security testing findings** from Akto. DefectDojo creates a Record for each Akto **API collection**.

#### Prerequisites

An Akto **API key**, created under **Settings \> Integrations \> Akto APIs** in the Akto dashboard. It is sent as the `X-API-KEY` header and is never logged.

#### Connector Mappings

1. Enter `https://app.akto.io` in the **Location** field for Akto's SaaS platform. If you run Akto self\-hosted, enter your own dashboard URL instead.
2. Enter your Akto API key in the **API Key** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each API collection becomes a Record. Only **open** issues are imported, so issues you resolve in Akto are reflected in DefectDojo on the next Sync. Both Akto SaaS and self\-hosted deployments use this connector — the only difference is the **Location** you supply.
