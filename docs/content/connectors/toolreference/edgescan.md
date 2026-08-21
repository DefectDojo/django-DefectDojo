---
title: "Edgescan"
description: "How to set up the Edgescan Upstream Connector for DefectDojo"
weight: 52
audience: pro
---
The Edgescan connector uses the Edgescan REST API to import open vulnerabilities across your whole Edgescan account. DefectDojo enumerates every Edgescan **asset** and creates a Record for each one, then imports that asset's open vulnerabilities as findings — there is no per\-asset configuration.

#### Prerequisites

You will need an Edgescan API token. Create one from your Edgescan account under **Account settings \> API tokens**: enter a label, click **Create**, and copy the generated token (it is shown only once). We recommend a dedicated account for the Connector so automated activity is easy to distinguish.

#### Connector Mappings

1. Enter your Edgescan URL in the **Location** field — `https://live.edgescan.com` for the standard hosted platform, or your tenant's host if different.
2. Enter your Edgescan API token in the **Secret** field. It is sent as the `X-API-TOKEN` header.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each Edgescan asset becomes a Record, and each open vulnerability on that asset is imported as a finding. Severity is mapped from Edgescan's numeric scale (1–5) to DefectDojo's Info–Critical, and CVE references, the CWE, and a CVSS v3 vector are included where Edgescan provides them.
