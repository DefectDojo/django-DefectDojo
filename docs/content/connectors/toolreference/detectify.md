---
title: "Detectify"
description: "How to set up the Detectify Upstream Connector for DefectDojo"
weight: 49
audience: pro
---
The Detectify connector imports **vulnerability findings** covering Application Scanning, Surface Monitoring and API Scanning in one connector. DefectDojo creates a Record for each **asset** in your account.

#### Prerequisites

A Detectify **API key**, from **Team settings \> API keys**. It is sent as the `X-Detectify-Key` header and never logged.

Optionally, you can also supply the **base64 secret** paired with that key to have DefectDojo HMAC\-sign its requests. This is a **Professional plan** feature; without it, DefectDojo uses key\-only authentication, which works on all plans.

#### Connector Mappings

1. Enter `https://api.detectify.com/rest` in the **Location** field.
2. Enter your Detectify API key in the **API Key** field.
3. Optionally, enter the base64 secret in the **API Secret** field to enable request signing. Leave it blank for key\-only authentication.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each asset becomes a Record, carrying its vulnerabilities from all three Detectify scanning products.
