---
title: "Scantist"
description: "How to set up the Scantist Upstream Connector for DefectDojo"
weight: 116
audience: pro
---
The Scantist connector imports **SCA and SAST findings** from Scantist. DefectDojo creates a Record for each **project** on the account.

#### Prerequisites

A Scantist **API token**, generated in the Scantist UI under your account settings.

#### Connector Mappings

1. Enter `https://api.scantist.io` in the **Location** field.
2. Enter the API token in the **API Token** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each project becomes a Record, and its findings come from that project's **most recent completed scan**.
