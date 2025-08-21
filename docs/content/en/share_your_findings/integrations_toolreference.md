---
title: "Integrators Tool Reference"
description: "Beta Feature"
weight: 1
---

Here are specific instructions detailing how to set up a DefectDojo Integration with a third party Issue Tracker.

## Azure DevOps Boards

### Instance Setup

- **Label** should be the label that you want to use to identify this integration.
- **Location** should be set to your Azure URL - for example `https://dev.azure.com/{your organization}`
- **Token** should be set to a personal access token from Azure.

Authentication with Azure DevOps requires a [personal access token](https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate?view=azure-devops&tabs=Windows)
with permissions set to "Read, Write and Manage" for "Work Items" for the Azure Project that you wish to work with.

### Issue Tracker Mapping

These details dictate how DefectDojo will map Finding or Finding Group attributes to a given Project in Azure DevOps:

#### Issue Tracker Mapping Details

The `Project ID` field corresponds to the name or the ID of the Project in Azure.

#### Severity Mapping Details

The attributes in the form are supplied as defaults, and are as follows:

- **Severity Field Name**: `/fields/Microsoft.VSTS.Common.Priority`
- **Info Mapping**: `4`
- **Low Mapping**: `4`
- **Medium Mapping**: `3`
- **High Mapping**: `2`
- **Critical Mapping**: `1`

#### Status Mapping Details

The attributes in the form are supplied as defaults and are as follows:

- **Status Field Name**: `/fields/System.State`
- **Active Mapping**: `To Do`
- **Closed Mapping**: `Done`
- **False Positive Mapping**: `Done`
- **Risk Accepted Mapping**: `Done`

## GitHub

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

## GitLab

The GitLab integration allows you to add issues to a [GitLab Project](https://docs.gitlab.com/ee/user/project/).

### Instance Setup

- **Label** should be the label that you want to use to identify this integration.
- **Location** should be set to the link to your GitLab server, for example `https://gitlab.com/`.
- **Token** should be set to a personal access token from GitLab. The token must have API scopes. See [GitLab’s guide to creating a personal access token](https://docs.gitlab.com/user/profile/personal_access_tokens/#create-a-personal-access-token).

### Issue Tracker Mapping

- **Project Name**: The name of the project in GitLab that you want to send issues to

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
