---
title: "Zimperium"
description: "How to set up the Zimperium Upstream Connector for DefectDojo"
weight: 145
audience: pro
---
The Zimperium connector imports **mobile application security findings** from Zimperium zScan. DefectDojo creates a Record for each zScan **mobile app**.

#### Prerequisites

A zScan **client ID and secret**, issued from **zConsole \> Account Management \> Authorizations** (the `ZSCAN_CLIENT_ID` and `ZSCAN_CLIENT_SECRET` values). DefectDojo exchanges them for a bearer token on each Sync; the secret is never logged.

#### Connector Mappings

1. Enter your **zConsole** host in the **Location** field.
2. Enter the client ID in the **Client ID** field.
3. Enter the client secret in the **Client Secret** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each zScan mobile app becomes a Record, carrying the findings of that app's **latest completed assessment**.
