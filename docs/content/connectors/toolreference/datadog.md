---
title: "Datadog"
description: "How to set up the Datadog Upstream Connector for DefectDojo"
weight: 45
audience: pro
---
The Datadog connector imports **Cloud Security findings** — misconfigurations, identity risks and vulnerabilities — from the Datadog security findings API. DefectDojo creates a Record for each **cloud account** the findings belong to, so no per\-resource configuration is needed.

#### Prerequisites

You will need two credentials from Datadog:

* An **API key**, from **Organization Settings \> API Keys**.
* An **application key**, from **Organization Settings \> Application Keys**, which must carry the **`security_monitoring_findings_read`** scope.

Neither key is ever logged by DefectDojo.

#### Connector Mappings

1. Enter your organization's Datadog **site** in the **Location** field — for example `https://api.datadoghq.com`. Organizations on the EU, US3, US5 or AP1 sites must use their own site hostname.
2. Enter the API key in the **API Key** field.
3. Enter the application key in the **Application Key** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each cloud account that has findings becomes a Record. DefectDojo respects Datadog's rate limits, backing off and retrying rather than failing the Sync.
