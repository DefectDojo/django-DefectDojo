---
title: "Quay"
description: "How to set up the Quay Upstream Connector for DefectDojo"
weight: 110
audience: pro
---
The Quay connector uses the Project Quay REST API to discover container repositories and import the vulnerability reports produced by Quay's built-in **Clair** scanner. DefectDojo creates a Record for each Quay **repository** and, on each Sync, reads the Clair security report of every active tag's image manifest.

#### Prerequisites

Security scanning (Clair) must be enabled on your Quay instance, and you will need a Quay **OAuth 2 access token**:

* In Quay, create (or open) an Organization, go to **Applications**, create an OAuth application, then **Generate Token** with at least the **Read repositories** scope. A dedicated application for DefectDojo is recommended.
* The token is sent as a Bearer token on every request and is never logged.

#### Connector Mappings

1. Enter your Quay base URL in the **Location** field, for example `https://quay.io` or your self-hosted `https://quay.example.com`. The URL must be HTTPS; do not include a trailing API path — DefectDojo constructs the API paths automatically.
2. Enter the OAuth access token in the **Secret** field.
3. Optionally, set a **Namespace** to restrict discovery to a single Quay organization or user. Leave blank to discover every repository the token can read.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

DefectDojo maps each Quay **repository** to a Record. For each repository it lists the active tags, deduplicates them to their unique image manifests (a manifest shared by multiple tags is scanned once), and reads each manifest's Clair report. Manifests Clair has not finished scanning (for example a multi-architecture manifest list, or an image still queued) are skipped until a later Sync. Each Clair vulnerability becomes a finding — the affected package is the component, the fixed version becomes the mitigation, and Clair's **Negligible**/**Unknown** severities are recorded as **Informational**.

See the [Project Quay API documentation](https://docs.projectquay.io/api_quay.html) and the [Clair documentation](https://quay.github.io/clair/) for more information.
