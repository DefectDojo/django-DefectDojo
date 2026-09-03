---
title: "Rapid7 InsightAppSec"
description: "How to set up the Rapid7 InsightAppSec Upstream Connector for DefectDojo"
weight: 112
audience: pro
---
The Rapid7 InsightAppSec connector imports **DAST vulnerability findings** from the InsightAppSec cloud platform, enriched with attack\-module metadata (for example *SQL Injection*), CVSS scores, and the evidence collected by the scan. DefectDojo creates a Record for each InsightAppSec **app**.

**Please note:** this Connector is distinct from the [Rapid7 InsightVM](/connectors/toolreference/rapid7_insightvm/) connector — InsightAppSec is Rapid7's cloud DAST product on the Insight platform, while InsightVM findings come from your own Security Console.

#### Prerequisites

An Insight platform account with InsightAppSec, and a platform **API key**: in the [Rapid7 Insight platform](https://insight.rapid7.com), open the settings (gear) menu \> **API Keys** and generate a **User Key** (any role) or an **Organization Key** (platform admins). Copy the key when it is shown — it is displayed only once.

You also need your platform **region**, visible in your Insight URL (for example `us`, `us2`, `us3`, `eu`, `ca`, `au`, or `ap`).

#### Connector Mappings

1. Enter your regional API endpoint in the **Location** field — for example `https://us.api.insight.rapid7.com` (replace `us` with your region).
2. Enter the Insight platform API key in the **API Key** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each InsightAppSec app becomes a Record. Only **open** vulnerabilities (Unreviewed or Verified) are imported — findings Rapid7 has marked Remediated, a False Positive, Ignored, or Duplicate are excluded, so reimport closes them in DefectDojo. Severities map directly (`SAFE` and `INFORMATIONAL` import as Info).
