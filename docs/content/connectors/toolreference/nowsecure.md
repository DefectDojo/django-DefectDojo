---
title: "NowSecure"
description: "How to set up the NowSecure Upstream Connector for DefectDojo"
weight: 95
audience: pro
---
The NowSecure connector imports **mobile application security findings**, covering both mobile SAST and DAST. DefectDojo creates a Record for each **mobile app** on the account.

#### Prerequisites

A NowSecure **Platform API token**, from **Profile \> Tokens \> Generate Token**. It is sent as a bearer token and never logged.

#### Connector Mappings

1. Enter `https://lab-api.nowsecure.com` in the **Location** field.
2. Enter the API token in the **API Token** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each mobile app becomes a Record, carrying the findings from that app's **latest assessment** — so results describe the current build rather than accumulating across assessments.
