---
title: "Holm Security"
description: "How to set up the Holm Security Upstream Connector for DefectDojo"
weight: 75
audience: pro
---
The Holm Security connector imports findings across **both** of Holm's asset classes — network/infrastructure scanning and web application scanning — through one connector. DefectDojo creates a Record for each **asset**.

#### Prerequisites

A Holm Security **API token**, from **Security Center \> API**. It is never logged.

#### Connector Mappings

1. Enter your **region's** API host in the **Location** field — for example `https://se-api.holmsecurity.com` for the Swedish region. Holm Security's API host is region\-specific, so this must match the region your account is in.
2. Enter the API token in the **API Token** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each asset becomes a Record, whether it was found by a network scan or a web scan.
