---
title: "Google Artifact Analysis"
description: "How to set up the Google Artifact Analysis Upstream Connector for DefectDojo"
weight: 66
audience: pro
---
The Google Artifact Analysis connector imports **container image vulnerability findings** from Google Cloud. DefectDojo creates a Record for each **active** GCP project the service account can list — no per\-image or per\-repository configuration is needed.

#### Prerequisites

A Google **service account** with the **Container Analysis Occurrences Viewer** role, and a **JSON key** for it. Neither the key nor the token derived from it is ever logged.

#### Connector Mappings

1. Leave the **Location** field at the default unless you use a non\-standard endpoint.
2. Paste the **entire contents** of the service account JSON key file into the **Service Account Key** field.
3. Optionally, set **Parent** to narrow the sync to `organizations/{id}`, `folders/{id}` or `projects/{id}`. Leave it blank to sync every project the service account can list.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each active GCP project becomes a Record, carrying the vulnerability occurrences Artifact Analysis has recorded against its images.
