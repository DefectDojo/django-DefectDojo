---
title: "Beagle Security"
description: "How to set up the Beagle Security Upstream Connector for DefectDojo"
weight: 23
audience: pro
---
The Beagle Security connector imports **DAST findings** from Beagle Security. DefectDojo creates a Record for each **verified** application in your Beagle project tree — applications that have not been verified are not imported.

#### Prerequisites

A Beagle Security **personal access token**, sent as a bearer token.

**Beagle access tokens expire.** When one does, Beagle returns an HTML error page rather than a JSON error, so an expired token can present as an unclear Sync failure. If a previously working connector starts failing, check the token first.

#### Connector Mappings

1. Enter your Beagle API URL in the **Location** field — `https://api.beaglesecurity.com/rest/v2`.
2. Enter the personal access token in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each verified application becomes a Record, and its findings come from that application's most recently **finished** test session — so a test still in progress does not replace your existing results.
