---
title: "HiddenLayer"
description: "How to set up the HiddenLayer Upstream Connector for DefectDojo"
weight: 74
audience: pro
---
The HiddenLayer connector imports **AI/ML model scan findings** from HiddenLayer's Model Scanner. DefectDojo creates a Record for each **scanned model**.

#### Prerequisites

A HiddenLayer API **client ID and client secret**, created under **Model Scanner \> API Access**. DefectDojo exchanges them for a short\-lived bearer token on each Sync; the secret is never logged.

#### Connector Mappings

1. Enter your tenant's regional API URL in the **Location** field — `https://api.us.hiddenlayer.ai` or `https://api.eu.hiddenlayer.ai`.
2. Enter the client ID in the **Client ID** field.
3. Enter the client secret in the **Client Secret** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

HiddenLayer returns model scan results as **SARIF** logs, and DefectDojo maps them the same way it maps an uploaded SARIF report — so these findings behave like SARIF imports elsewhere in the Asset.
