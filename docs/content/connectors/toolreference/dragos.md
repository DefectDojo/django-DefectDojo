---
title: "Dragos"
description: "How to set up the Dragos Upstream Connector for DefectDojo"
weight: 51
audience: pro
---
The Dragos connector imports **OT/ICS vulnerability findings** from a Dragos SiteStore deployment. DefectDojo creates a Record for each **OT zone** — one SiteStore deployment represents one site, so the zone is the meaningful grouping within it.

#### Prerequisites

A Dragos **API key ID and secret**, created under **Admin \> Users \> Add New API Key**. The key needs these read privileges:

* `asset:read`
* `detection:read`
* `vulnerability:read`

The secret is shown only once when the key is generated, so capture it then. It is never logged.

#### Connector Mappings

1. Enter your Dragos **SiteStore** host in the **Location** field.
2. Enter the API key ID in the **API Key ID** field.
3. Enter the secret in the **API Key Secret** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each OT zone becomes a Record, carrying the vulnerabilities detected on the assets in that zone.
