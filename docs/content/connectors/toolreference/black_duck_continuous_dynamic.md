---
title: "Black Duck Continuous Dynamic"
description: "How to set up the Black Duck Continuous Dynamic Upstream Connector for DefectDojo"
weight: 27
audience: pro
---
The Black Duck Continuous Dynamic connector imports **DAST findings** from the Continuous Dynamic platform. DefectDojo creates a Record for each **site** on your account, with no per\-site configuration.

**Please note:** findings from this connector use the **WhiteHat Sentinel** scan type. Continuous Dynamic was sold as WhiteHat Sentinel Dynamic before the acquisition, and DefectDojo reuses that established mapping — so this is expected, not a misconfiguration.

#### Prerequisites

A Continuous Dynamic **API key**, from **Account \> API Keys**. Black Duck treats this key as equivalent to a username and password, so store it accordingly.

#### Connector Mappings

1. Enter `https://sentinel.whitehatsec.com` in the **Location** field.
2. Enter the API key in the **API Key** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each site becomes a Record. DefectDojo requests attack vectors, risk scores and descriptions from the API so that findings arrive complete — the same detail the file\-based WhiteHat Sentinel parser expects.
