---
title: "GitGuardian"
description: "How to set up the GitGuardian Upstream Connector for DefectDojo"
weight: 62
audience: pro
---
The GitGuardian connector uses the GitGuardian REST API to import **secret incidents** — exposed credentials GitGuardian has detected across your monitored sources. DefectDojo creates a Record for each monitored source (repository or perimeter) that currently has open incidents, and imports each open incident as a finding.

For your security, the connector imports only incident **metadata** — the detector, severity, validity, status, and a link back to GitGuardian. The exposed secret value itself is never retrieved or stored by DefectDojo; follow the link in each finding to review the affected locations in GitGuardian.

#### Prerequisites

You will need a GitGuardian API key. We recommend a **Service Account token** (rather than a personal access token) so automated activity is easy to distinguish. Create it under **API** in the GitGuardian dashboard and grant these read scopes:

* `incidents:read`
* `sources:read`

#### Connector Mappings

1. Enter your GitGuardian API URL in the **Location** field: `https://api.gitguardian.com` for the SaaS platform, or your self-hosted instance's API URL.
2. Enter the API key in the **Secret** field.

Only **open** incidents (status `TRIGGERED` or `ASSIGNED`) are imported; incidents you resolve or ignore in GitGuardian are automatically mitigated in DefectDojo on the next sync. A confirmed-live secret (validity *valid*) is imported as a verified finding.
