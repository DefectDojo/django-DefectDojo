---
title: "Cyberwatch"
description: "How to set up the Cyberwatch Upstream Connector for DefectDojo"
weight: 43
audience: pro
---
The Cyberwatch connector imports **CVEs and security (compliance) issues** from a Cyberwatch appliance — both kinds in a single Sync. DefectDojo creates a Record for each asset, or "server", the appliance knows about.

#### Prerequisites

A Cyberwatch **API key ID and secret key**, created in the appliance under **Profile \> API keys**. The secret is never logged.

#### Connector Mappings

1. Enter your Cyberwatch appliance URL in the **Location** field.
2. Enter the API key ID in the **API Key** field.
3. Enter the secret in the **Secret Key** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each asset becomes a Record, carrying both its CVEs and its compliance findings.
