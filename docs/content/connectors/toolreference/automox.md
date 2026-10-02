---
title: "Automox"
description: "How to set up the Automox Upstream Connector for DefectDojo"
weight: 19
audience: pro
---
The Automox connector imports **missing patches** from Automox. DefectDojo creates a Record for each Automox **device group**.

**A finding here is a missing patch**, not a scanner result — this connector reports patches Automox is waiting to apply, so use it to track patch coverage rather than as a vulnerability scanner.

#### Prerequisites

An Automox **API key**, from **Settings \> API** in the Automox console. It is sent as a bearer token and never logged.

#### Connector Mappings

1. Enter `https://console.automox.com/api` in the **Location** field.
2. Enter your Automox API key in the **API Key** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each device group becomes a Record, carrying the patches awaiting installation on the devices in that group.
