---
title: "Palo Alto Cortex XSIAM"
description: "How to set up the Palo Alto Cortex XSIAM Upstream Connector for DefectDojo"
weight: 102
audience: pro
---
The Cortex XSIAM connector imports **alerts** from your Cortex XSIAM tenant as findings (`Cortex XSIAM:Alerts`). Because XSIAM alerts span endpoints, cloud, network and identity, DefectDojo creates a single Record for the whole **tenant** rather than one per asset.

#### Prerequisites

A Cortex XSIAM **API Key** and its **API Key ID**, created in the XSIAM console under **Settings \> Configurations \> Integrations \> API Keys**. Use a **Standard** security\-level key — the connector signs each request with the `Authorization` and `x-xdr-auth-id` headers.

Assign the key a **Role** with read access to **Alerts and Incidents** (for the imported alerts); the credential check also reads **Endpoints**. A built\-in **Viewer** role, or a custom role with those **View** permissions, is the minimum.

#### Connector Mappings

1. Enter your tenant's API base URL in the **Location** field — the FQDN shown on the API Keys page, for example `https://api-\<your-tenant\>.xdr.us.paloaltonetworks.com`.
2. Enter the **API Key ID**.
3. Enter the **API Key** secret.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

All of the tenant's alerts import under the single XSIAM tenant Record.
