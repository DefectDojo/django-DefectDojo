---
title: "Bitbucket"
description: "Upstream and Downstream Connector setup for Bitbucket"
weight: 25
audience: pro
---
## Upstream Connector

The Bitbucket connector is an **Asset Connector**: it enumerates the repositories in the Bitbucket Cloud workspaces you name and creates a DefectDojo Asset for each repository, grouped into Organizations by Bitbucket project. No findings are imported.

#### Prerequisites

Bitbucket Cloud requires a **scoped** Atlassian API token — classic (unscoped) Atlassian API tokens are rejected by Bitbucket with an "API Token provided has no Bitbucket scopes" error.

1. Go to [id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens) and choose **Create API token with scopes**.
2. Select the **Bitbucket** app, then grant the read scopes: `read:account:bitbucket`, `read:workspace:bitbucket`, `read:repository:bitbucket`, and `read:project:bitbucket`.

Only Bitbucket Cloud (bitbucket.org) is supported. Bitbucket Server reached end of life in 2024, and Bitbucket Data Center is not supported.

#### Connector Mappings

1. Enter `https://bitbucket.org` in the **Location** field.
2. Enter the Atlassian account email the token belongs to in the **Email** field.
3. Enter the scoped API token in the **Secret** field.
4. Enter one or more workspace slugs (comma-separated) in the **Workspace Slugs** field. This field is required: Bitbucket's scoped API tokens cannot list workspaces automatically, so DefectDojo needs to be told which workspaces to read.

Each repository becomes a Record named after the repository, grouped by its Bitbucket **project**.

## Downstream Connector

The Bitbucket integration allows you to push issues to the [issue tracker](https://support.atlassian.com/bitbucket-cloud/docs/enable-an-issue-tracker/) of a Bitbucket Cloud repository.

The issue tracker is optional in Bitbucket and must be enabled on the repository before DefectDojo can create Issues in it. To enable it, open the repository in Bitbucket and select **Repository settings**, then enable the issue tracker under **Features**.

### Instance Setup

- **Label** should be the label that you want to use to identify this integration.
- **Location** should be set to `https://bitbucket.org`.
- **Email** should be the email address of the Atlassian account that the API token belongs to.
- **API Token** should be set to a scoped Atlassian API token.

Bitbucket app passwords are deprecated by Atlassian and will not work with this integration. To create an API token:

1. Open [Atlassian account settings](https://id.atlassian.com/manage-profile/security/api-tokens) and choose **Security**, then **Create and manage API tokens**.
2. Choose **Create API token with scopes**, name the token, and set an expiry date.
3. Select **Bitbucket** as the app.
4. Grant the token permission to read repositories and to read and write issues.

### Issue Tracker Mapping

- **Workspace** should be the slug of the workspace that contains the repository, as it appears in bitbucket.org URLs.
- **Repository Slug** should be the slug of the repository that you want to create Issues in.

### Severity Mapping Details

This maps to the Bitbucket issue Priority field. The attributes in the form are supplied as defaults, and each value must be one of Bitbucket's priorities: `trivial`, `minor`, `major`, `critical`, or `blocker`.

- **Severity Field Name**: `priority`
- **Info Mapping**: `trivial`
- **Low Mapping**: `minor`
- **Medium Mapping**: `major`
- **High Mapping**: `critical`
- **Critical Mapping**: `blocker`

### Status Mapping Details

This maps to the Bitbucket issue State field. Each value must be one of Bitbucket's issue states: `new`, `open`, `resolved`, `on hold`, `invalid`, `duplicate`, `wontfix`, or `closed`.

- **Status Field Name**: `state`
- **Active Mapping**: `new`
- **Closed Mapping**: `resolved`
- **False Positive Mapping**: `invalid`
- **Risk Accepted Mapping**: `wontfix`
