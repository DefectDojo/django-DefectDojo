---
title: "Veracode"
description: "How to set up the Veracode Upstream Connector for DefectDojo"
weight: 137
audience: pro
---
The Veracode connector imports application findings from the Veracode platform, split by scan type into **SAST**, **DAST**, **SCA**, and **Manual** finding types. DefectDojo creates a Record for each Veracode **application**.

#### Prerequisites

Generate a Veracode **API credential** for an account that can see the applications you want to import: in the Veracode Platform, open your account menu \> **API Credentials** and select **Generate API Credentials** (see [Managing Veracode API credentials](https://docs.veracode.com/r/c_api_credentials3)). Copy both the **API ID** and the **API Secret Key** — the secret is shown only once.

#### Connector Mappings

1. Enter the Veracode API base URL in the **Location** field: `https://api.veracode.com` (commercial region), `https://api.veracode.eu` (European region), or `https://api.veracode.us` (US federal region).
2. Enter the API ID in the **API ID** field.
3. Enter the API secret key in the **Secret** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each Veracode application becomes a Record. Only **open** findings are imported, so reimport closes findings Veracode reports as resolved.
