---
title: "AppCheck"
description: "How to set up the AppCheck Upstream Connector for DefectDojo"
weight: 17
audience: pro
---
The AppCheck connector imports **DAST vulnerability findings** from the AppCheck NG platform. DefectDojo discovers every scan on your account and creates a Record for each **scan** — there is no per\-scan configuration.

#### Prerequisites

An AppCheck **API key**, from the **API** section of your AppCheck account.

**Treat this key like a password.** AppCheck sends it as part of the request path rather than in a header, so it forms part of the URL. DefectDojo registers the key for redaction and never logs a full request URL, but apply the same care wherever else you store it.

#### Connector Mappings

1. Enter `https://api.appcheck-ng.com` in the **Location** field.
2. Enter your AppCheck API key in the **API Key** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each scan becomes a Record, and its findings come from that scan's most recent **completed** run — so a scan that is still in flight never truncates the finding set. AppCheck fans a scan out across several engines (its own scanner, **Nmap**, and **OpenVAS**) and normalizes the output, so each finding carries the engine that reported it.
