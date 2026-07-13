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

## Jira

The Jira integration pushes DefectDojo Findings and Finding Groups to a Jira project as issues, keeps each issue's status in sync with the Finding, and links the Finding back to the created issue. Both Jira **Cloud** and **Data Center / Server** are supported. Jira Service Management is not supported.

### Choosing an authentication method

Set **Jira Deployment** first, then pick an **Authentication Method**:

**Jira Cloud**
- **API Token (email + token)** — HTTP Basic auth using an Atlassian account email and an [API token](https://id.atlassian.com/manage-profile/security/api-tokens). Calls go directly to your site URL.
- **OAuth 2.0 (recommended)** — a one-time browser consent; DefectDojo obtains and refreshes the tokens for you.
- **Service Account Token** — a scoped API token created for an Atlassian [service account](https://support.atlassian.com/user-management/docs/manage-api-tokens-for-service-accounts/).

**Jira Data Center / Server**
- **Personal Access Token (recommended)**
- **Username + Password**

> **How Cloud auth reaches Jira:** OAuth 2.0 and Service Account both authenticate as a Bearer token against Atlassian's gateway — `https://api.atlassian.com/ex/jira/{cloudId}` — which is a *different host* than your `https://your-site.atlassian.net` site URL. DefectDojo uses the gateway for every API call but always builds the ticket link shown on a Finding from your **site URL**, so the link a user clicks is a normal, browsable `.../browse/{ISSUE-KEY}` link. (API Token and Data Center auth call the site URL directly, so there is no split.)

### Instance Setup

- **Label** should be the label you want to use to identify this integration.
- **Location** should be set to your Jira **site URL**, for example `https://your-organization.atlassian.net`. This is used for the browsable ticket links, and — for API Token and Data Center auth — as the API base URL.
- The remaining fields depend on the method you chose above (email + API token, OAuth client credentials, service-account token, PAT, or username + password).

### OAuth 2.0 setup (Cloud)

Create a dedicated app in the [Atlassian developer console](https://developer.atlassian.com/console/myapps/), then connect from DefectDojo.

1. Choose **Create → OAuth 2.0 integration**. It must be an *OAuth 2.0 integration* — a Connect or Forge app cannot use the 3LO authorization-code grant (you'd get `grant_type is not enabled for client`).
2. When prompted for **Access type**, choose **Resource-level**. This scopes the token to the single Jira site the user authorizes, which is exactly what one DefectDojo connection targets. (**Account-level** grants access to every site in the Atlassian account — broader than needed.)
3. Under **Permissions**, add the **Jira platform REST API** and grant the scopes listed below. Note: `offline_access` is *not* listed here — it is a standard OAuth scope DefectDojo requests in the authorization URL, not something you add on this screen.
4. Under **Authorization**, next to **OAuth 2.0 (3LO)** click **Configure** and set the **Callback URL** to `https://<your-defectdojo-host>/integrators/jira/oauth/callback` — it must match your DefectDojo site URL exactly. Enabling this is what turns on the authorization-code grant and refresh tokens; skipping it causes the `grant_type is not enabled` / `Client is not allowed to use offline_access` errors.
5. Copy the **Client ID** and **Client Secret** into the DefectDojo form and **Submit** to save the connection.
6. Click **Connect with Jira** and approve the consent screen. Atlassian redirects back to DefectDojo, which stores the tokens and resolves your `cloudId` automatically. A "Connected" indicator appears when it succeeds.

> The callback host is your DefectDojo `SITE_URL`. Atlassian must be able to redirect the browser there, and the value must match what DefectDojo sends exactly — so use the real hostname your users reach DefectDojo at, not a value only reachable from inside the network.

#### Minimum OAuth scopes

DefectDojo requests these four classic scopes by default, and they are also the **absolute minimum** required — each one backs a specific behavior:

| Scope | Required for |
|-------|--------------|
| `read:jira-work` | Reading the project, issues, and available transitions (connection validation and status sync). |
| `write:jira-work` | Creating and editing issues, and executing status transitions. |
| `read:jira-user` | The connection's identity check — DefectDojo calls `/myself` when validating access. |
| `offline_access` | Issuing a **refresh token**. Without it the access token expires (~1 hour after you connect) and the connection stops working, because DefectDojo can no longer refresh it. |

Atlassian recommends classic scopes over granular ones; the four above keep the app's footprint minimal and are sufficient for everything the integration does.

##### Granular scope alternative

If your organization requires **granular** scopes instead of classic, the minimum equivalent set is:

| Granular scope | Required for |
|----------------|--------------|
| `read:user:jira` | The `/myself` identity check. |
| `read:project:jira` | Validating the target project exists. |
| `read:issue:jira` | Reading an issue's current status during sync. |
| `write:issue:jira` | Creating and editing issues **and executing status transitions** — there is no separate transition-write scope; a transition is a write to the issue. |
| `read:issue.transition:jira` | Listing the transitions available on an issue. |
| `offline_access` | The refresh token (same as classic). |

Depending on your site's field configuration, an endpoint may also require companion read scopes to expand fields — most commonly `read:status:jira` and `read:field:jira` (and `read:issue-meta:jira` for create). If a push fails with a `403` "scope does not match" error, add the exact scope named in the error. This companion-scope sprawl is precisely why classic scopes are recommended.

For the **Service Account Token** method, grant the token `read:jira-work` and `write:jira-work` (plus `read:jira-user`) — or the granular equivalents above without `offline_access`. `offline_access` does not apply — a service-account token is long-lived and is not refreshed by DefectDojo.

### Issue Tracker Mapping

- **Project Key**: the key of the Jira project to create issues in, for example `SEC`.
- **Issue Type**: the issue type to create, for example `Bug` or `Task`. Defaults to `Bug`.

### Severity Mapping Details

Defaults match Jira's default priority scheme. Edit them to match the priority names in your project:

- **Severity Field Name**: `priority`
- **Info Mapping**: `Lowest`
- **Low Mapping**: `Low`
- **Medium Mapping**: `Medium`
- **High Mapping**: `High`
- **Critical Mapping**: `Highest`

### Status Mapping Details

Statuses vary per project workflow, so these defaults are meant to be edited to **your** workflow's status names:

- **Status Field Name**: `status`
- **Active Mapping**: `To Do`
- **Closed Mapping**: `Done`
- **False Positive Mapping**: `Done`
- **Risk Accepted Mapping**: `Done`

### Custom Fields (optional)

You can map additional Jira fields — for example a required `resolution` on close, or `labels` — in the mapping's **Custom Fields** step. Each custom-field mapping has four parts:

- **Source** — where the value comes from: an attribute of the **Finding**, **Test**, **Engagement**, or **Asset** being pushed, or a **Static value**.
- **Value** — for an object source, the specific attribute to read, chosen from a list of that object's fields with human-readable labels (for example *Severity*, *CVE*, *Mitigation*). For a **Static value** source this is a free-text box you type the literal value into.
- **Vendor Field** — the Jira field to write to. Because DefectDojo can read Jira's field catalog, this is a searchable picker that lists each field by its **display name** and resolves it to the internal id for you — so you select *DD Close Justification* and DefectDojo stores `customfield_10255`. The picker is populated from the connection, so it works once the connection is saved and validated.
- **Application point** — *when* to send the field: on **ticket creation**, on **every update**, or as part of a specific status **transition** (Active / Closed / False Positive / Risk Accepted). A transition-scoped field is sent as part of that transition's edit — this is how you supply a value Jira only accepts on a transition screen, most commonly a `resolution` your workflow requires when an issue is resolved.

### Ticket Templates (optional)

By default Jira issues use DefectDojo's built-in title and body. To customize them, attach a **Ticket Template** to the mapping in its **Ticket Template** step. A template defines four independently-optional pieces — the **Finding** summary and description, and the **Finding Group** summary and description. Any piece left blank falls back to the built-in default, so you can override just the title, just the body, or all four. Use **Test render** in the template editor to preview the rendered output against sample data — catching mistakes such as unknown placeholders or values that exceed a field's length limit — before saving. If a template is later deleted, the mappings that used it revert to the built-in defaults automatically.

### How it works

- **Create / Update / Delete:** creating pushes a new issue and records the link on the Finding; updating edits the existing issue; deleting a Finding force-closes its issue (nothing is deleted in Jira). Pushes can be manual ("Push to Integrators") or automatic per the Issue Tracker Assignment.
- **Status reconciliation:** after creating (and on every update) DefectDojo reads the issue's current status and, if it differs from the mapped target, finds a single workflow transition that reaches it and applies it. If no such transition exists, the mapping records an error rather than failing silently. Any transition-scoped custom fields are sent with that transition.
- **Ticket link:** the link surfaced on the Finding is `https://your-site.atlassian.net/browse/{ISSUE-KEY}` — always your public site URL, never the internal gateway.
- **Token lifecycle (OAuth):** DefectDojo owns the whole flow — it performs the authorization-code exchange, stores the access and refresh tokens, and refreshes on demand before a push, persisting the new refresh token each time (Atlassian rotates it on every refresh).
- **Credential storage:** all connection credentials (passwords, tokens, client secrets, OAuth tokens) are encrypted at rest and are never returned through the API — editing a connection shows a "leave blank to keep" placeholder for stored secrets.

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
