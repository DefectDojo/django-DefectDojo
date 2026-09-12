---
title: "Palo Alto Cortex XDR"
description: "How to set up the Palo Alto Cortex XDR Upstream Connector for DefectDojo"
weight: 102
audience: pro
---
The Cortex XDR connector imports **alerts** from your Cortex XDR tenant as findings (`Cortex XDR:Alerts`). DefectDojo creates a Record for each Cortex **endpoint**.

#### Prerequisites

A Cortex XDR **API Key** and its **API Key ID**, created in the Cortex console under **Settings \> Configurations \> Integrations \> API Keys**. Use a **Standard** security\-level key — the connector signs each request with the `Authorization` and `x-xdr-auth-id` headers.

Assign the key a **Role** that grants read access to the data the connector reads: **Endpoints** (required, for endpoint discovery via `get_endpoints`) and **Alerts and Incidents** (for the imported alerts). A built\-in **Viewer** role, or a custom role with those two **View** permissions, is the minimum.

#### Connector Mappings

1. Enter your tenant's API base URL in the **Location** field — the FQDN shown on the API Keys page, for example `https://api-\<your-tenant\>.xdr.us.paloaltonetworks.com` (the region segment varies by tenant).
2. Enter the **API Key ID** (the integer shown beside the key).
3. Enter the **API Key** secret.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each Cortex endpoint becomes a Record, named for its hostname and OS.
