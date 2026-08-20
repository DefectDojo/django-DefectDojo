---
title: "NetRise"
description: "How to set up the NetRise Upstream Connector for DefectDojo"
weight: 92
audience: pro
---
The NetRise connector imports **firmware vulnerability findings** from NetRise. DefectDojo enumerates every firmware artifact in your tenant and creates a Record for each **product line** — the vendor and Asset pair — so a product line accumulates the findings of its artifacts.

#### Prerequisites

A NetRise API **client ID and secret**, plus the **organization ID** they belong to. The secret is never logged.

#### Connector Mappings

1. Enter your NetRise API URL in the **Location** field.
2. Enter the client ID in the **Client ID** field.
3. Enter the client secret in the **Client Secret** field.
4. Enter your **Organization ID**.
5. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each product line becomes a Record, carrying the CVEs found in its firmware artifacts.
