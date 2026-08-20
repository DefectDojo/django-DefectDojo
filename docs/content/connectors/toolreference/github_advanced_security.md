---
title: "GitHub Advanced Security"
description: "How to set up the GitHub Advanced Security Upstream Connector for DefectDojo"
weight: 64
audience: pro
---
The GitHub Advanced Security connector imports **code scanning**, **Dependabot**, and **secret scanning** alerts from GitHub, as three separate finding types (`GitHub:CodeScanning`, `GitHub:Dependabot`, and `GitHub:SecretScanning`). DefectDojo discovers every non\-archived repository in the configured organization and creates a Record for each one.

#### Prerequisites

GitHub Advanced Security features must be enabled for the repositories you want to import. The connector authenticates with a GitHub **personal access token**:

1. In GitHub, open **Settings \> Developer settings \> Personal access tokens** and create a token owned by (or with access to) the target organization.
2. Grant it read access to the security alerts: a *fine\-grained* token needs **Read\-only** access to **Code scanning alerts**, **Dependabot alerts**, and **Secret scanning alerts** on the organization's repositories; a *classic* token needs the **`repo`** and **`security_events`** scopes.
3. Confirm the token's owner can see the repositories you intend to import — the connector only sees repositories the token can access.

#### Connector Mappings

1. Enter `https://api.github.com` in the **Location** field. For GitHub Enterprise Server, use `https://<your-host>/api/v3`.
2. Enter the organization login in the **Organization** field.
3. Enter the personal access token in the **Secret** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each non\-archived repository becomes a Record, queried across the three alert families for open alerts. An alert family that is not enabled for a repository is skipped rather than reported as resolved, so disabled features do not cause false closures.
