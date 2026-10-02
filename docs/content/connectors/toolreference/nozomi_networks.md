---
title: "Nozomi Networks"
description: "How to set up the Nozomi Networks Upstream Connector for DefectDojo"
weight: 96
audience: pro
---
The Nozomi Networks connector imports **OT/ICS vulnerability findings** from Nozomi Vantage. DefectDojo creates a Record for each **network zone**, so one Record represents one zone of your operational network.

#### Prerequisites

A Vantage **access key name** and **key token**, created under **Administration \> Security \> Access Keys**. DefectDojo exchanges them for a short\-lived session token on each Sync; the key token is never logged.

#### Connector Mappings

1. Enter `https://api.vantage.nozominetworks.io` in the **Location** field.
2. Enter the access key name in the **Key Name** field.
3. Enter the key token in the **Key Token** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

This connector imports **vulnerabilities only** — it does not import alert-log events — and only those Vantage still reports as **unresolved**, so vulnerabilities you resolve in Vantage are reflected in DefectDojo on the next Sync.
