---
title: "Action1"
description: "How to set up the Action1 Upstream Connector for DefectDojo"
weight: 11
audience: pro
---
The Action1 connector imports **endpoint vulnerability findings** from Action1. DefectDojo creates a Record for each **endpoint (host)**.

#### Prerequisites

An Action1 **API key and secret** pair. The key acts as the OAuth client ID and the secret is never logged.

#### Connector Mappings

1. Enter `https://app.action1.com/api/3.0` in the **Location** field.
2. Enter the API key in the **API Key (Client ID)** field.
3. Enter the API secret in the **API Secret** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

**One finding is created per endpoint-and-vulnerability pair**, so a single CVE present on fifty hosts produces fifty findings, each attached to its own host's Record. This is what makes per\-host remediation tracking possible, but it does mean finding counts scale with fleet size rather than with the number of distinct CVEs.
