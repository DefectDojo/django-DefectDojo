---
title: "SOOS"
description: "How to set up the SOOS Upstream Connector for DefectDojo"
weight: 129
audience: pro
---
The SOOS connector imports **SCA findings** from SOOS. DefectDojo creates a Record for each **project** on the account.

#### Prerequisites

**Two credentials — neither works on its own:**

* Your **Client ID**, which forms part of every request path.
* Your **API Key**, sent as a request header.

Both are found under **SOOS \> Integrations**.

#### Connector Mappings

1. Enter `https://api.soos.io/api/` in the **Location** field.
2. Enter your SOOS **Client ID**.
3. Enter your SOOS **API Key**.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each project becomes a Record, carrying its scanned dependencies' vulnerabilities.
