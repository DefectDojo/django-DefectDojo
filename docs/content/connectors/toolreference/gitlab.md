---
title: "GitLab"
description: "Upstream and Downstream Connector setup for GitLab"
weight: 65
audience: pro
---
## Upstream Connector

The GitLab connector is an **Asset Connector**: it enumerates every project (repository) your token can access and creates a DefectDojo Asset for each one, grouped into Organizations by GitLab namespace (group or user). No findings are imported.

#### Prerequisites

You will need a Personal Access Token with the **read_api** scope. We recommend creating the token from a dedicated service account; the connector lists the projects that account is a member of.

#### Connector Mappings

1. Enter your GitLab URL in the **Location** field: `https://gitlab.com`, or the base URL of your self-hosted instance.
2. Enter the Personal Access Token in the **Secret** field.

Each project becomes a Record named after the project, grouped by its **namespace**. Projects that are pending deletion in GitLab (deleted by a user, but not yet purged by GitLab's background job) are excluded automatically, so deleting a project flags its Record as `MISSING` on the next Sync instead of leaving behind a renamed ghost asset.

## Downstream Connector

The GitLab integration allows you to add issues to a [GitLab Project](https://docs.gitlab.com/ee/user/project/).

### Instance Setup

- **Label** should be the label that you want to use to identify this integration.
- **Location** should be set to the link to your GitLab server, for example `https://gitlab.com/`.
- **Token** should be set to a personal access token from GitLab. The token must have API scopes. See [GitLab’s guide to creating a personal access token](https://docs.gitlab.com/user/profile/personal_access_tokens/#create-a-personal-access-token).

### Issue Tracker Mapping

- **Project Name**: The name of the project in GitLab that you want to send issues to.

### Severity Mapping Details

This maps to the GitLab Priority field.
- **Severity Field Name**: `Priority`
- **Info Mapping**: `1`
- **Low Mapping**: `2`
- **Medium Mapping**: `3`
- **High Mapping**: `4`
- **Critical Mapping**: `5`

### Status Mapping Details

By default, GitLab has statuses of 'opened' and 'closed'.  Additional status labels can be added if you want to track False Positive or Risk Accepted status.  See [GitLab Docs](https://docs.gitlab.com/user/work_items/status/) for details.

- **Status Field Name**: `Status`
- **Active Mapping**: `opened`
- **Closed Mapping**: `closed`
- **False Positive Mapping**: `closed`
- **Risk Accepted Mapping**: `closed`
