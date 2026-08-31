---
title: "Socket"
description: "How to set up the Socket Upstream Connector for DefectDojo"
weight: 126
audience: pro
---
The Socket connector uses the [Socket.dev](https://socket.dev) API to import **software supply-chain findings** — Socket's alerts on your dependencies (malware, typosquats, install scripts, known vulnerabilities and 70+ other categories). DefectDojo discovers every repository across the organizations your token can access and creates a Record for each, then imports the alerts from that repository's latest full scan.

#### Prerequisites

You will need a Socket **API token** — an organization token created in the Socket dashboard under **Settings → API Tokens** (with the `repo:list` and full-scan read scopes). The token is sent as a bearer token and is never logged.

#### Connector Mappings

1. Keep the pre-filled **Location**, `https://api.socket.dev/v0`, or enter it explicitly.
2. Enter the Socket API token in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

DefectDojo maps each **repository** to a Record and imports the alerts from its most recent full scan. Each alert becomes a finding: the severity comes from Socket's own rating (low, medium, high, critical), the affected package becomes the component and a PURL, the alert category (supply-chain risk, quality, maintenance, vulnerability, license) is recorded as tags, and the alert details are carried into the description. Findings are recorded as static findings and de-duplicated on Socket's alert key.

See the [Socket API documentation](https://docs.socket.dev/reference) for more information.
