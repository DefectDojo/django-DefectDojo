---
title: "Cloudflare"
description: "How to set up the Cloudflare Upstream Connector for DefectDojo"
weight: 36
audience: pro
---
The Cloudflare connector imports **Security Center insights** — security posture issues Cloudflare surfaces about your account and zones, such as a missing DMARC record, DNSSEC not being enabled, or a certificate problem. DefectDojo creates a Record for each zone (domain) that has open insights, plus an account-level Record for insights that are not tied to a specific zone.

#### Prerequisites

You will need a Cloudflare **API token** (not the legacy Global API Key). Create one under **My Profile > API Tokens > Create Token** in the Cloudflare dashboard. The quickest option is the **"Read all resources"** template; for a least-privilege token, grant **Zone > Zone > Read** (all zones) plus account-level read access for Security Center.

#### Connector Mappings

1. Enter `https://api.cloudflare.com/client/v4` in the **Location** field.
2. Enter the API token in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

DefectDojo auto-discovers the accounts and zones the token can access — no account ID is required. Only open (active, non-dismissed) insights are imported, so insights you resolve or dismiss in Cloudflare are automatically mitigated in DefectDojo on the next sync.
