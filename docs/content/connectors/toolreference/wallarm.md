---
title: "Wallarm"
description: "How to set up the Wallarm Upstream Connector for DefectDojo"
weight: 139
audience: pro
---
The Wallarm connector imports **API security findings** from Wallarm. DefectDojo creates a Record for each **affected domain**.

#### Prerequisites

A Wallarm **API token**, from **Console \> Settings \> API tokens**. A **Read Only** role is sufficient, and the token is never logged.

#### Connector Mappings

1. Enter your Wallarm cloud URL in the **Location** field — `https://api.wallarm.com` for the EU cloud or `https://us1.api.wallarm.com` for the US cloud.
2. Enter the API token in the **API Token** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each affected domain becomes a Record, carrying the account's API security vulnerabilities that affect it.
