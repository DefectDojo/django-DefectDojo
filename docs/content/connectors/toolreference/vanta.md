---
title: "Vanta"
description: "How to set up the Vanta Upstream Connector for DefectDojo"
weight: 136
audience: pro
---
The Vanta connector imports **failing compliance tests** from Vanta. DefectDojo creates a Record for each Vanta **integration**, plus an organization\-wide catch\-all for tests that belong to none.

#### Prerequisites

An OAuth **client ID and secret** from Vanta. Create them under **Settings \> Developer Console** as a **"Manage Vanta"** app — other app types will not have the access this connector needs.

#### Connector Mappings

1. Enter your Vanta API URL in the **Location** field.
2. Enter the OAuth client ID in the **Client ID** field.
3. Enter the client secret in the **Client Secret** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each **failing resource of a failing test** becomes a finding, grouped under the integration the test belongs to — so a single failing control across many resources produces a finding per resource.
