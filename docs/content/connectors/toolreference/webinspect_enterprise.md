---
title: "WebInspect Enterprise"
description: "How to set up the WebInspect Enterprise Upstream Connector for DefectDojo"
weight: 141
audience: pro
---
The WebInspect Enterprise connector imports **DAST findings** from a WebInspect Enterprise (WIE) server. DefectDojo creates a Record for each **application** the token can see.

#### Prerequisites

A WebInspect Enterprise **API token**. WIE accepts a Fortify\-style API token, and it is never logged.

#### Connector Mappings

1. Enter your WebInspect Enterprise server URL in the **Location** field.
2. Enter the API token in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each application becomes a Record, and its findings come from that application's **most recent completed scan**.
