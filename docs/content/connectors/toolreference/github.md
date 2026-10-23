---
title: "GitHub"
description: "Upstream and Downstream Connector setup for GitHub"
weight: 63
audience: pro
---
## Upstream Connector

The GitHub connector is an **Asset Connector**: it enumerates the repositories your token can access and creates one Record per repository. Each Record can become a DefectDojo Asset. No findings are imported.

The Asset's Organization comes from the repository's GitHub owner. A repository owned by a GitHub organization goes in a DefectDojo Organization named after that organization's display name (the **Name** on its GitHub profile, not its login). A repository owned by a personal account, or by an organization with no display name set, goes in the default **GitHub Connector** Organization.

> **🔑 Important: Assets only, not findings.** This connector discovers your repository **inventory** and nothing else. Connecting it will not bring in code scanning, Dependabot or secret scanning alerts, and the Assets it creates stay empty of findings. To get findings from GitHub, use the separate [GitHub Advanced Security](/connectors/toolreference/github_advanced_security/) connector, or import a scan file. The two connectors are independent and can be run together.

#### Prerequisites

The connector authenticates with a GitHub **personal access token** and reads only repository **metadata** (name, description, URL, and owner) — it does not access your code, issues, or security alerts. It discovers every repository the token's account owns, collaborates on, or reaches through organization or team membership, so confirm the token's account can see the repositories you want to mirror. We recommend a dedicated service account.

The token only needs read-only access to repository metadata:

- A *fine-grained* token needs **Repository permissions → Metadata: Read-only**, granted to the repositories (or the whole organization) you want to import.
- A *classic* token needs the **`repo`** scope to include private repositories (use **`public_repo`** if you only need public ones), plus **`read:org`** so organization-owned repositories resolve.

Only GitHub.com (including GitHub Enterprise Cloud) is supported. GitHub Enterprise **Server** is not supported by this connector at this time.

#### Connector Mappings

1. Enter `https://api.github.com` in the **Location** field.
2. Enter the personal access token in the **Secret** field.

No organization or repository list needs to be entered: DefectDojo imports every repository the token can see. Each repository becomes a Record named after the repository, and its Asset goes in an Organization as described above. If a repository is later deleted, or the token loses access to it, its mapped Record is flagged `MISSING` on the next Sync rather than removed. DefectDojo never silently deletes an Asset.

#### Mapping repositories to existing Assets, and choosing which repositories to import

If you already have Assets for some of your repositories, or only want some repositories in DefectDojo, turn **Auto-Mapping** off before the first Discover. With Auto-Mapping off:

- Every discovered repository is listed as a **New** Record, and nothing else happens. An unmapped Record does not create an Asset.
- To attach a repository to an Asset you already have, go to **Connectors**, open the GitHub connection, find the repository under **Records**, and choose **Edit Record** from its **⋮** menu. Pick any existing Asset from the drop-down. The Asset's name does not have to match the repository's name, so an Asset called `payments-service` can be mapped to a repository called `pay-svc`.
- Map only the repositories you want. The rest can stay **New**, or you can **Ignore** them so they drop out of your list of Records waiting to be mapped.

Mapping a Record to an Asset from **Edit Record** requires DefectDojo Pro 3.2.400 or later. That covers both attaching a New Record to an existing Asset and pointing a mapped Record at a different Asset. Earlier releases do not show the Asset drop-down for GitHub Records. See [Manage Records](/connectors/upstream/manage_records/#edit-records-remap-ignore-or-delete) for the full set of Record actions, and [Auto-Mapping](/connectors/upstream/manage_records/#auto-mapping) for how Auto-Mapping picks an Asset when it is on.

#### Troubleshooting: a repository is missing

The connector can only discover what its token can see. If a repository you expect is not among the Records after a Discover:

- **Check the token's access.** Sign in to GitHub as the token's account and confirm it can open the repository. A *fine-grained* token only covers the repositories (or organization) it was granted, and the organization may need to approve the token before it works. A *classic* token needs `repo` for private repositories and `read:org` for organization repositories.
- **Check SSO authorization.** If the organization uses SAML single sign-on, a classic token must be authorized for that organization (in GitHub, **Settings → Developer settings → Personal access tokens**, then **Configure SSO** next to the token). Until it is, the organization's repositories are invisible to the token.
- **Check the connector version.** Repositories that the account reaches only through **team** membership are discovered from connectors release 3.2.300 onward. On earlier releases they do not appear.

After fixing access, run **Discover** again.

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
