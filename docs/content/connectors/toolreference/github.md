---
title: "GitHub"
description: "Upstream and Downstream Connector setup for GitHub"
weight: 63
audience: pro
---
## Upstream Connector

The GitHub connector is an **Asset Connector**: it enumerates the repositories your token can access and creates a DefectDojo Asset for each one, grouped into Organizations by GitHub owner (organization or user). No findings are imported.

**Please note:** this connector imports your repository **inventory** only. To import findings from GitHub — code scanning, Dependabot, and secret scanning alerts, or issues from the repository issue tracker — use the separate [GitHub Advanced Security](/connectors/toolreference/github_advanced_security/) connector. The two are independent and can be run together.

#### Prerequisites

The connector authenticates with a GitHub **personal access token** and reads only repository **metadata** (name, description, URL, and owner) — it does not access your code, issues, or security alerts. It imports every repository the token's account owns, collaborates on, or is an organization member of, so confirm the token's account can see the repositories you want to mirror. We recommend a dedicated service account.

The token only needs read-only access to repository metadata:

- A *fine-grained* token needs **Repository permissions → Metadata: Read-only**, granted to the repositories (or the whole organization) you want to import.
- A *classic* token needs the **`repo`** scope to include private repositories (use **`public_repo`** if you only need public ones), plus **`read:org`** so organization-owned repositories resolve.

Only GitHub.com (including GitHub Enterprise Cloud) is supported. GitHub Enterprise **Server** is not supported by this connector at this time.

#### Connector Mappings

1. Enter `https://api.github.com` in the **Location** field.
2. Enter the personal access token in the **Secret** field.

No organization or repository list needs to be entered — DefectDojo imports every repository the token can see. Each repository becomes a Record named after the repository, grouped by its GitHub **owner** (organization or user). If a repository is later deleted, or the token loses access to it, its mapped Record is flagged `MISSING` on the next Sync rather than removed — DefectDojo never silently deletes an Asset.

## Downstream Connector

The GitHub integration allows you to add issues to a [GitHub Project](https://docs.github.com/en/issues/planning-and-tracking-with-projects/learning-about-projects/about-projects), which also open Issues in an associated Repo.  These Repos/Projects can be associated with either a GitHub Organization or a personal GitHub account.

### Instance Setup

- **Label** should be the label that you want to use to identify this integration.
- **Location** should be set to your GitHub User or Organization URL, depending on where you wish to create issues. for example `https://github.com/{your-organization}`
- **Token** should be set to a personal access token from GitHub.

Personal access tokens for GitHub can be created at https://github.com/settings/tokens.  The token must have Repo and Project scopes.

### Issue Tracker Mapping

- **Issue Tracker Mapping Label** should be set to identify the Project or Repo that you wish to create Issues in.
- **Project Number** should be the ID of a GitHub project that you want to send items to.  You can get this from the URL while looking at a Project, for example `https://github.com/orgs/{your-org}/projects/{project number}`.
- **Repository Name** should be the name of a repo associated with your organization (or user) that you want to push Issues to.


### Severity Mapping Details

**In order to set up the integration, the Project MUST have a custom field created to represent Issue Priority, otherwise Severity will not be mapped correctly and Issues will not push to GitHub.**

Follow this guide to create a [custom field](https://docs.github.com/en/issues/planning-and-tracking-with-projects/learning-about-projects/quickstart-for-projects#creating-a-field-to-track-priority).
Each Severity will need to have a corresponding single-select option available.  For example, out of the box DefectDojo suggests P0, P1, P2, P3, P4 as possible Priority values, and each of those will need to be added to the Priority custom field.

- **Severity Field Name**: `Priority`
- **Info Mapping**: `P0`
- **Low Mapping**: `P1`
- **Medium Mapping**: `P2`
- **High Mapping**: `P3`
- **Critical Mapping**: `P4`

### Status Mapping Details

By default, new GitHub Projects will have Statuses for Issues of "In Progress" and "Done".  Additional statuses can be added to the Project to track False Positive or Risk Accepted status if you wish.  One of the ways this can be done is by adding a new Status Column to the Project Board.

- **Status Field Name**: `Status`
- **Active Mapping**: `In Progress`
- **Closed Mapping**: `Done`
- **False Positive Mapping**: `Done`
- **Risk Accepted Mapping**: `Done`
