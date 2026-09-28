---
title: "Google Cloud SCC"
description: "How to set up the Google Cloud SCC Upstream Connector for DefectDojo"
weight: 67
audience: pro
---
The Google Cloud SCC connector uses the Security Command Center v2 REST API to import active security findings from your Google Cloud organization, folder, or project. DefectDojo creates a Record for each Google Cloud **project** that has open findings.

#### Prerequisites

Security Command Center must be **activated** on your organization (the Standard tier is free). You will then need a service account that can list findings, and a JSON key for it:

1. In Google Cloud, create a service account — a dedicated one for DefectDojo is recommended.
2. Grant it the **Security Center Findings Viewer** role (`roles/securitycenter.findingsViewer`) at the scope you want to import (organization, folder, or project).
3. Create a **JSON key** for the service account and download it.

#### Connector Mappings

1. Leave the **Location** field at the default `https://securitycenter.googleapis.com` unless you use a non-standard endpoint.
2. In the **Parent Resource** field, enter the scope to import from: `organizations/{id}`, `folders/{id}`, or `projects/{id}`.
3. Paste the full contents of the service-account **JSON key** file into the **Service Account Key** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Only `ACTIVE`, un-muted findings are imported, so findings you deactivate or mute in SCC are automatically mitigated in DefectDojo on the next sync. Each finding's affected GCP project becomes its Record.
