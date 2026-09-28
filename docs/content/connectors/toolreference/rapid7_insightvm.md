---
title: "Rapid7 InsightVM"
description: "How to set up the Rapid7 InsightVM Upstream Connector for DefectDojo"
weight: 113
audience: pro
---
The Rapid7 InsightVM connector imports asset vulnerability findings from your InsightVM **Security Console** (API v3), enriched with the console's global vulnerability catalog. DefectDojo creates a Record for each InsightVM **site**.

#### Prerequisites

Network access from DefectDojo to your Security Console, and a console **user account** — its login is used for HTTP Basic authentication. The console API is served on port **3780** by default.

#### Connector Mappings

1. Enter your Security Console URL, including the port, in the **Location** field — for example `https://console.example.com:3780`.
2. Enter the console username in the **Username** field.
3. Enter the console password in the **Secret** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each InsightVM site becomes a Record; the connector walks the site's assets and imports their vulnerable findings.
