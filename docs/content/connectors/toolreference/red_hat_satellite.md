---
title: "Red Hat Satellite"
description: "How to set up the Red Hat Satellite Upstream Connector for DefectDojo"
weight: 114
audience: pro
---
The Red Hat Satellite connector imports **errata** from your Satellite inventory as findings. DefectDojo enumerates every host and folds the fleet into Records along one Katello dimension of your choosing.

**This is broader than "vulnerabilities."** Every applicable erratum on every host becomes a finding — that includes RHSA security advisories **and** bugfix and enhancement advisories. Use a **Minimum Severity** if you only want the security ones.

#### Prerequisites

A Satellite login with the **`view_hosts`** and **`view_content_views`** permissions. Satellite has no token endpoint, so the credentials are sent with every request over HTTP Basic authentication, and the password is never logged.

#### Connector Mappings

1. Enter your Satellite server URL in the **Location** field — for example `https://satellite.example.com`.
2. Enter the Satellite username in the **Username** field.
3. Enter the password in the **Password** field.
4. Optionally, set **Asset Grouping** to choose how hosts are folded into Records: `host-collection`, `lifecycle-environment`, `content-view`, or `host` for one Record per host. Leave it blank for `host-collection`.
5. Optionally, set **Skip TLS Verification** to `true` if your Satellite server uses the self\-signed certificate a default Satellite or Foreman install generates for itself. Leave it blank to verify certificates.
6. Optionally, set a **Minimum Severity** to limit which findings are imported.

Hosts that share a grouping value share a Record, and a new host joins the right Record automatically on the next Discover — so the mapping keeps up with your fleet without per\-host configuration.
