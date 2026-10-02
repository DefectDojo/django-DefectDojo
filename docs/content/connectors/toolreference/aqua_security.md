---
title: "Aqua Security"
description: "How to set up the Aqua Security Upstream Connector for DefectDojo"
weight: 18
audience: pro
---
The Aqua Security connector imports **container image and workload vulnerability findings** across your whole Aqua tenant. DefectDojo creates a Record for each scanned **registry/repository**.

#### Prerequisites

An **admin-generated** Aqua **API key and secret**, created under **Account Management \> API Keys**. The secret is shown only once when the key is generated, so capture it at that point. Neither value is ever logged.

#### Connector Mappings

1. Enter your Aqua tenant URL in the **Location** field — `https://<your-tenant>.cloud.aquasec.com`. DefectDojo appends the API path itself.
2. Enter the API key in the **API Key** field.
3. Enter the API secret in the **API Secret** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each scanned registry/repository becomes a Record, and its image and workload vulnerabilities are imported as findings.
