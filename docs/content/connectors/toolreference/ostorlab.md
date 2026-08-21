---
title: "Ostorlab"
description: "How to set up the Ostorlab Upstream Connector for DefectDojo"
weight: 101
audience: pro
---
The Ostorlab connector imports **mobile, web and attack-surface findings** — all three of Ostorlab's asset classes through one connector. DefectDojo creates a Record for each **scanned asset**, which may be an app bundle ID, a domain, or a host.

#### Prerequisites

An Ostorlab **API key**, created under **Settings \> API Keys**. It is sent as the `X-Api-Key` header and is never logged.

#### Connector Mappings

1. Enter `https://api.ostorlab.co` in the **Location** field. DefectDojo appends the GraphQL API path itself.
2. Enter your Ostorlab API key in the **API Key** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each scanned asset becomes a Record, and the vulnerabilities from every scan of that asset are imported against it.
