---
title: "Jira"
description: "How to set up the Jira Downstream Connector for DefectDojo"
weight: 82
audience: pro
---
The Jira integration pushes DefectDojo Findings and Finding Groups to a Jira project as issues, keeps each issue's status in sync with the Finding, and links the Finding back to the created issue. With [two-way sync](#two-way-sync), Jira status changes and comments come back to the Finding too. Both Jira **Cloud** and **Data Center / Server** are supported. Jira Service Management is not supported.

### Choosing an authentication method

Set **Jira Deployment** first, then pick an **Authentication Method**:

**Jira Cloud**
- **API Token (Email + Token)** — HTTP Basic auth using an Atlassian account email and an [API token](https://id.atlassian.com/manage-profile/security/api-tokens). Calls go directly to your site URL.
- **OAuth 2.0 (Recommended)** — a one-time browser consent; DefectDojo obtains and refreshes the tokens for you.
- **Service Account Token** — a scoped API token created for an Atlassian [service account](https://support.atlassian.com/user-management/docs/manage-api-tokens-for-service-accounts/).

**Jira Data Center / Server**
- **Personal Access Token (Recommended)**
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
6. Click **Connect With Jira** and approve the consent screen. Atlassian redirects back to DefectDojo, which stores the tokens and resolves your `cloudId` automatically. A "Connected" indicator appears when it succeeds.

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

#### Coming back from Jira

When [two-way sync](#two-way-sync) is on, the status mapping also says what a Jira change means for the Finding. The status lists take Jira's status **category** keys, never status names, and the resolution lists are matched regardless of case:

- **Closing Status Categories**: categories that close the Finding, from `new` (To Do), `indeterminate` (In Progress) and `done`. Default `done`.
- **Reopening Status Categories**: categories that reopen a closed Finding. Default `new` and `indeterminate`.
- **False Positive Resolutions**: resolutions that close the Finding as a false positive.
- **Accepted Risk Resolutions**: resolutions that close the Finding as an accepted risk.

A resolution in neither list closes the Finding as mitigated. Leave a list empty to use the receiver's default. The resolution defaults come from your classic Jira instance when you have exactly one (the migration from classic Jira also copies them onto each migrated mapping). With several classic instances, no defaults are imposed: set the resolutions on each mapping. An issue linked through the classic Jira integration always reads the resolutions of the classic instance configured for its own site, so each classic instance's URL must be its Jira site's base URL.

The form warns when an outbound status would come back as the opposite change, for example when **Active Mapping** names a status in the `done` category, which two-way sync would read as a closure.

### Custom Fields (optional)

You can map additional Jira fields — for example a required `resolution` on close, or `labels` — in the mapping's **Custom Fields** step. Each custom-field mapping has four parts:

- **Source** — where the value comes from: an attribute of the **Finding**, **Test**, **Engagement**, or **Asset** being pushed, or a **Static value**.
- **Value** — for an object source, the specific attribute to read, chosen from a list of that object's fields with human-readable labels (for example *Severity*, *CVE*, *Mitigation*). For a **Static value** source this is a free-text box you type the literal value into.
- **Vendor Field** — the Jira field to write to. Because DefectDojo can read Jira's field catalog, this is a searchable picker that lists each field by its **display name** and resolves it to the internal id for you — so you select *DD Close Justification* and DefectDojo stores `customfield_10255`. The picker is populated from the connection, so it works once the connection is saved and validated.
- **Application point** — *when* to send the field: on **ticket creation**, on **every update**, or as part of a specific status **transition** (Active / Closed / False Positive / Risk Accepted). A transition-scoped field is sent as part of that transition's edit — this is how you supply a value Jira only accepts on a transition screen, most commonly a `resolution` your workflow requires when an issue is resolved.

#### Select-list fields

For a Jira select list, type the option name as a static value, for example `High`. DefectDojo reads the field's type from Jira and sends the option in the shape Jira expects. For a multi-select list, separate the options with commas (`team-a, team-b`). You can still enter the JSON Jira accepts, such as `{"id": "10421"}` to pick an option by its id; a JSON value is sent unchanged. A dynamic source that resolves to an option name, such as a Finding's *Severity*, is handled the same way.

### Ticket Templates (optional)

By default Jira issues use DefectDojo's built-in title and body. To customize them, attach a **Ticket Template** to the mapping in its **Ticket Template** step. A template defines four independently-optional pieces — the **Finding** summary and description, and the **Finding Group** summary and description. Any piece left blank falls back to the built-in default, so you can override just the title, just the body, or all four. Use **Test render** in the template editor to preview the rendered output against sample data — catching mistakes such as unknown placeholders or values that exceed a field's length limit — before saving. If a template is later deleted, the mappings that used it revert to the built-in defaults automatically.

### Push notes as comments (optional)

Turn on **Push Notes as Comments** on the mapping to post new notes on a linked Finding to its Jira issue as comments, made by the connection's account.

- Every public note attached to the Finding is posted, however it was added: the API (`POST /api/v2/findings/{id}/notes/`), the classic UI, the Pro UI, a bulk edit, or closing the Finding with a note.
- Private notes are never posted.
- The comment reads `(Author name): note text`. The note is sent in full, up to Jira's comment length limit (a longer one is cut and ends with `[truncated]`).
- Markdown is converted to Jira formatting. Mentions (`[~accountid:...]`), images and macros are escaped and show as plain text, so a note cannot ping a Jira user.
- A note on a grouped Finding goes to the Finding Group's issue. The same text is posted to one group issue once within ten minutes, so a bulk action on many members of a group adds one comment, not one per member.
- A Finding with no issue yet gets no comment: a note never creates an issue.
- Notes added by Triage Engine rules, including the ones two-way sync adds from Jira comments, are never sent back.
- Editing or deleting a note does not change the comment.

With classic scopes, posting comments needs no scope beyond `write:jira-work`. With granular scopes, Atlassian's reference for the Add comment operation lists `write:comment:jira` together with the read scopes `read:comment:jira`, `read:comment.property:jira`, `read:group:jira`, `read:project:jira`, `read:project-role:jira`, `read:user:jira` and `read:avatar:jira`. Atlassian changes these lists from time to time, so check its [REST API reference](https://developer.atlassian.com/cloud/jira/platform/rest/v2/api-group-issue-comments/#api-rest-api-2-issue-issueidorkey-comment-post) if a comment fails with a `403` naming a scope.

Posting comments also needs a go-integrators version that provides it. Until one is deployed, each mapping records one integration error saying so, and posting is tried again an hour later.

### Two-way sync

The connector pushes to Jira. To have Jira talk back, open the connection and choose **Turn On Two-Way Sync**. This creates a Triage Engine [webhook receiver](/automation/triage_engine/webhook_receivers/) bound to the connection, and the rule that acts on its deliveries:

- An issue moving into a closed status category closes the linked Finding, as a false positive or an accepted risk when its resolution is in that list.
- An issue moving back to an open category reopens the Finding.
- A comment on the issue is added to the Finding as a note, once. Comments DefectDojo posted itself are recognized and skipped.

The receiver's **Setup** tab gives the URL and the steps to create the webhook in Jira. Because the receiver is bound to one connection, two Jira sites with overlapping project keys never touch each other's Findings. A connection has one two-way sync receiver; when somebody else turned it on, the connection shows **Managed by another user**.

If Jira changes do not arrive, see [two-way sync troubleshooting](/connectors/downstream/troubleshooting_jira/#two-way-sync-changes-from-jira-are-not-reaching-findings).

### How it works

- **Create / Update / Delete:** creating pushes a new issue and records the link on the Finding; updating edits the existing issue; deleting a Finding force-closes its issue (nothing is deleted in Jira). Pushes can be manual (**Push to Connector**) or automatic per the Issue Tracker Assignment. A manual push only sends when an Issue Tracker Assignment covers the Finding's Engagement or Asset; otherwise nothing is sent, and DefectDojo says that no connector is assigned.
- **Comment:** with **Push Notes as Comments** on, a new note on a Finding is added to its issue as a comment.
- **Status reconciliation:** after creating (and on every update) DefectDojo reads the issue's current status and, if it differs from the mapped target, finds a single workflow transition that reaches it and applies it. If no such transition exists, the mapping records an error rather than failing silently. Any transition-scoped custom fields are sent with that transition.
- **Ticket link:** the link surfaced on the Finding is `https://your-site.atlassian.net/browse/{ISSUE-KEY}` — always your public site URL, never the internal gateway.
- **Token lifecycle (OAuth):** DefectDojo owns the whole flow — it performs the authorization-code exchange, stores the access and refresh tokens, and refreshes on demand before a push, persisting the new refresh token each time (Atlassian rotates it on every refresh).
- **Credential storage:** all connection credentials (passwords, tokens, client secrets, OAuth tokens) are encrypted at rest and are never returned through the API — editing a connection shows a "leave blank to keep" placeholder for stored secrets.
