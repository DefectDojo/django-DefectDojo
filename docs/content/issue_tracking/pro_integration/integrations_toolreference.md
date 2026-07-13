---
title: "Integrators Tool Reference"
description: "Detailed setup guides for Integrators"
weight: 1
audience: pro
aliases:
  - /en/share_your_findings/integrations_toolreference
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

## Bitbucket

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

## ServiceNow

The ServiceNow Integration allows you to push DefectDojo Findings as ServiceNow Incidents.

### Instance Setup

Your ServiceNow instance will require you to obtain a Refresh Token, associated with the User or Service account that will push Incidents to ServiceNow.

You'll need to start by creating an OAuth registration on your ServiceNow instance for DefectDojo:

1. In the left-hand navigation bar, search for “Application Registry” and select it.
2. Click “New”.
3. Choose “Create an OAuth API endpoint for external clients”.
4. Fill in the required fields:
    * Name: Provide a meaningful name for your application (e.g., Vulnerability Integration Client).
    * (Optional) Adjust the Token Lifespan:
    * Access Token Lifespan: Default is 1800 seconds (30 minutes).
    * Refresh Token Lifespan: The default is 8640000 seconds (approximately 100 days).
5. Click Submit to create the application record.
6. After submission, select the application from the list and take note of the **Client ID and Client Secret** fields.

You will then need to use this registration to obtain a Refresh Token, which can only be obtained through the ServiceNow API.  Open a terminal window and paste the following (substituting the variables wrapped in `{{}}` with your user's actual information)

```
curl --request POST \
 --url {{INSTANCE_HOST}}/oauth_token.do \
 --header 'content-type: application/x-www-form-urlencoded' \
 --data grant_type=password \
 --data 'client_id={{CLIENT_ID}}' \
 --data 'client_secret={{CLIENT_SECRET}}' \
 --data 'username={{USERNAME}}' \
 --data 'password={{PASSWORD}}'
 ```

If your ServiceNow credentials are correct, and allow for admin level-access to ServiceNow, you should receive a response with a RefreshToken.  You'll need that token to complete integration with DefectDojo.

- **Instance Label** should be the label that you want to use to identify this integration.
- **Location** should be set to the URL for your ServiceNow server, for example `https://your-organization.service-now.com/`.
- **Refresh Token** is where the Refresh Token should be entered.
- **Client ID** should be the Client ID set in the OAuth App Registration.
- **Client ID** should be the Client Secret set in the OAuth App Registration.

### Severity Mapping Details

This maps to the ServiceNow Impact field.
- **Info Mapping**: `1`
- **Low Mapping**: `1`
- **Medium Mapping**: `2`
- **High Mapping**: `3`
- **Critical Mapping**: `3`

### Status Mapping Details

- **Status Field Name**: `State`
- **Active Mapping**: `New`
- **Closed Mapping**: `Closed`
- **False Positive Mapping**: `Resolved`
- **Risk Accepted Mapping**: `Resolved`

## Freshservice

The Freshservice Integration allows you to push DefectDojo Findings and Finding Groups as Freshservice tickets, assigned to an agent Group of your choice.

### Instance Setup

- **Label** should be the label that you want to use to identify this integration.
- **Location** should be set to your Freshservice URL: `https://yourcompany.freshservice.com`.
- **API Key** should be a Freshservice API key.  Find it by clicking your profile picture (top right) > **Profile settings** - the key appears on the right below the **Delegate Approvals** section, after you complete the captcha.  If no key is shown there, API access may be disabled at the account level and an administrator has to enable it first.
- **Requester Email** should be the email address tickets are requested on behalf of.  Freshservice requires a requester on every ticket, so DefectDojo creates tickets with this address as the requester.

### Issue Tracker Mapping

- **Group ID** should be the numeric ID of the Freshservice agent group tickets will be assigned to.  Find it in the URL while viewing the group under **Admin > Agent Groups**.
- **Workspace ID** (optional) routes tickets to a specific workspace on multi-workspace accounts.  Leave it empty to use the primary workspace.

### Severity Mapping Details

This maps to the Freshservice ticket **Priority** field, which uses numeric codes (`1` Low, `2` Medium, `3` High, `4` Urgent).  The priority names are also accepted:

- **Severity Field Name**: `Priority`
- **Info Mapping**: `1`
- **Low Mapping**: `1`
- **Medium Mapping**: `2`
- **High Mapping**: `3`
- **Critical Mapping**: `4`

### Status Mapping Details

This maps to the ticket **Status** field, which uses numeric codes (`2` Open, `3` Pending, `4` Resolved, `5` Closed).  The status names are also accepted:

- **Status Field Name**: `Status`
- **Active Mapping**: `2`
- **Closed Mapping**: `5`
- **False Positive Mapping**: `5`
- **Risk Accepted Mapping**: `3`

A few Freshservice-specific behaviors to be aware of:

- Updates sync the full ticket content - Freshservice allows the subject and description to be edited after creation.
- Tickets are closed rather than deleted when a Finding is removed; tickets already Resolved or Closed are left untouched.  A resolution note is attached automatically on closure, so accounts that require one (a common business rule) accept the close.
- Some accounts compute a ticket's priority from an Impact/Urgency matrix or a business rule and ignore the priority sent at creation.  DefectDojo detects this and re-applies the mapped priority with a follow-up update, so the mapping still takes effect.
