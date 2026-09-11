---
title: "Palo Alto Cortex XSOAR"
description: "How to set up the Palo Alto Cortex XSOAR Upstream Connector for DefectDojo"
weight: 102
audience: pro
---
The Cortex XSOAR connector imports **incidents** from your XSOAR tenant as findings (`Cortex XSOAR`). DefectDojo creates a single Record for the **tenant**.

#### Prerequisites

An XSOAR **API Key**, created in the console under **Settings \> Integrations \> API Keys**. For **Cortex XSOAR 8** / Cortex multi\-tenant, also copy the **API Key ID** (sent as the `x-xdr-auth-id` header); leave it blank for XSOAR 6.

The key's **Role** must grant **read access to incidents** — used to search incidents. A read\-only role is the minimum.

#### Connector Mappings

1. Enter your XSOAR API base URL in the **Location** field — for a Cortex\-hosted tenant this is the FQDN from the API Keys page, for example `https://api-\<your-tenant\>.xsoar.paloaltonetworks.com`; for a self\-hosted XSOAR use your server's base URL.
2. Enter the **API Key**.
3. Optionally, enter the **API Key ID** (XSOAR 8 / Cortex multi\-tenant only).
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each XSOAR incident becomes a finding under the tenant Record.
