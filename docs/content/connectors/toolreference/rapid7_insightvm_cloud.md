---
title: "Rapid7 InsightVM - Cloud Instance"
description: "How to set up the Rapid7 InsightVM - Cloud Instance Upstream Connector for DefectDojo"
weight: 113
audience: pro
---
The Rapid7 InsightVM - Cloud Instance connector imports asset vulnerability findings from InsightVM hosted on the **Rapid7 Insight platform** (Cloud Integrations API v4), enriched with the platform's vulnerability catalog. DefectDojo creates a Record for each InsightVM **site**.

**Please note:** this Connector is for InsightVM running on the Rapid7 Insight cloud platform. If your findings come from your own on\-premises **Security Console**, use the [Rapid7 InsightVM](/connectors/toolreference/rapid7_insightvm/) connector instead, which authenticates with console credentials rather than a platform API key.

#### Prerequisites

An Insight platform account with InsightVM, and a platform **API key**: in the [Rapid7 Insight platform](https://insight.rapid7.com), open the settings (gear) menu \> **API Keys** and generate a **User Key** (any role) or an **Organization Key** (platform admins). Copy the key when it is shown, because it is displayed only once.

You also need your platform **region**, visible in your Insight URL (for example `us`, `us2`, `us3`, `eu`, `ca`, `au`, or `ap`).

#### Connector Mappings

1. Enter your regional API endpoint in the **Location** field, for example `https://us.api.insight.rapid7.com` (replace `us` with your region). This field is pre\-filled with the US endpoint.
2. Enter the Insight platform API key in the **API Key** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each InsightVM site becomes a Record; the connector reads the platform's integration assets and imports their vulnerable findings, enriched from the vulnerability catalog. Findings import under the same **Rapid7 InsightVM - Connectors Import** type as the on\-premises connector, so results from both connectors deduplicate together.
