---
title: "Jira (Legacy)"
description: "Work with the Jira integration"
weight: 1
audience: pro
aliases:
  - /issue_tracking/jira/pro__jira_guide/
  - /en/share_your_findings/jira_guide
---
> **This page documents the legacy Jira integration.** The per\-Asset Jira integration described here has been superseded by the **[Jira Downstream Connector](/connectors/downstream/about/)**, which is generally available on every DefectDojo Pro instance and is the recommended way to push Findings to Jira. In the Pro sidebar, **Connect > Jira** carries a `LEGACY` badge for this reason — see [Menu Badges](/navigation/pro__menu_badges/).
>
> **If you are setting up Jira for the first time, start with the [Downstream Connector](/connectors/downstream/about/) instead of this guide.**
>
> **Already using the legacy integration?** DefectDojo Pro includes a built\-in migration that moves your existing classic Jira configuration onto Downstream Connectors, including the tickets you have already pushed — see [Migrating to the Jira Downstream Connector](#migrating-to-the-jira-downstream-connector) below.
>
> The legacy integration continues to work, and this guide remains accurate for it.

DefectDojo's Jira integration can be used to push Finding data to one or more Jira Spaces.  By doing so, you can integrate DefectDojo into your standard development workflow.  Here are some examples of how this can work:

* The AppSec team can selectively push Findings to a Jira Space used by developers, so that issue remediation can be appropriately prioritized alongside regular development.  Developers on this board don't need to access DefectDojo - they can keep all their work in one place.
* DefectDojo can push ALL Findings to a bidirectional Jira Space which the AppSec team uses, which allows them to split up issue validation.  This board keeps in sync with DefectDojo and allows for complex remediation workflows.
* DefectDojo can selectively push Findings from separate Assets &/or Engagements to separate Jira Spaces, to keep things in their proper context.

## Migrating to the Jira Downstream Connector

DefectDojo Pro can convert an existing classic Jira setup into Downstream Connector configuration for you, rather than making you rebuild it by hand.

**Where to find it:** go to **Connect \> Downstream** to open the **Downstream Connectors** page, and use the **Classic Jira Migration** card. Click **Migrate from classic Jira**, then confirm.

The card only appears if there is classic Jira configuration to migrate, or a previous run to report — so an instance that never used classic Jira will not see it. Once everything has been migrated the card remains but the button is disabled, because there is nothing left to do.

Running the migration requires **global Maintainer-level permissions** (specifically, permission to edit integrations), and it must be run from a logged-in browser session — it cannot be driven with an API token.

### What happens to tickets you have already pushed

**Your existing Jira tickets are kept and re-linked — they are not orphaned, and the connector does not open duplicates.** Every Finding that classic Jira had already pushed keeps its ticket, and the connector takes over updating that same ticket in place. Links on Finding Groups carry over the same way.

The one exception is **Engagement epics**. The Downstream Connector has no concept of epics, so epic issues are reported in the migration's warnings and left untouched.

### What gets migrated

* Your Jira **instance** connection — URL and credentials — becomes a Downstream Connector integration instance, keeping its name.
* **Severity mappings** and **status mappings** (your open and close transition keys) are carried across.
* Each **Jira Project** configuration becomes an issue tracker mapping, keeping its project key and issue type, and stays assigned to the same Asset or Engagement.
* **Push All Issues** is preserved: projects that had it enabled keep pushing automatically.
* **Custom fields**, **close/reopen transition fields**, **component**, **default assignee**, and **labels** are converted to field mappings. Where you used *Add Vulnerability Id as a Jira label*, that becomes a label mapping too.
* A **custom issue template** directory becomes a ticket template. The stock templates are not copied, because the connector already ships equivalents.

### What does not carry over

These are reported as warnings on the migration run — they do not stop it. Look for the *"things the connector cannot carry over"* list in the results.

* **Jira → DefectDojo reverse sync.** This is the important one. The Downstream Connector does not sync changes *back* from Jira, so resolution mappings that apply Risk Acceptance or False Positive from a Jira resolution are not migrated. **If you rely on reverse sync, leave the classic Jira instance configured** — the migration does not remove it.
* **Engagement Epic Mapping** — the connector has no epic concept.
* **Push Notes**, **SLA notification comments**, and **risk acceptance expiration comments** — the connector does not post these to Jira.
* Custom fields named `summary`, `description`, `project`, `issuetype` or `status` — these are reserved by the connector, and a field mapping using one is skipped.
* Custom field values longer than 512 characters — skipped rather than truncated.
* A Jira Project attached to neither an Asset nor an Engagement produces no assignment.

### What happens to the classic integration afterward

**Nothing pushes twice.** For each project it migrates, the migration switches the classic Jira project off, so only the connector pushes from that point on. You do not need to disable anything manually.

Your classic configuration is **kept, not deleted** — the instance, project and issue records all remain, with only the push settings turned off. That is deliberate: it is what makes the change reversible, and it is what keeps reverse sync working if you depend on it.

**To roll back**, re-enable the classic Jira project settings and remove the connector configuration the migration created. There is no one-click undo.

**Re-running is safe.** The migration records what it has already converted and skips it on a second run, so nothing is duplicated. If a project or instance fails, the rest still migrates — a failed project is left running on the classic integration rather than being switched off, so it keeps working while you investigate.

### While it runs

The migration runs in the background and reports progress as it goes. When it finishes you get a summary — how many connectors, mappings, assignments, templates and ticket links were created, how many classic projects were switched off, and anything skipped — along with the warnings described above. Only one migration runs at a time.

# Setting Up Jira

Setting Up Jira requires the following steps:
1. Enable the Jira integration in System Settings.  Until you do, the rest of the Jira settings are hidden throughout DefectDojo.
2. Connect a Jira Instance, either with a username / password or an API token.  Multiple instances can be linked.
3. Add that Jira Instance to one or more Assets or Engagements within DefectDojo.
4. If you wish to use bidirectional sync, create a Jira Webhook which will send updates to DefectDojo.

## Step 1: Enable the Jira integration in System Settings

The Jira integration is off by default, and while it is off DefectDojo hides every other Jira control in the interface.  This is the first thing to configure: none of the steps below are available until it is enabled.

While the integration is disabled, there is no **Jira Instances** entry in the sidebar, so there is nowhere to add a Jira Instance:

![image](images/jira-menu-hidden-pro.png)

### Enable the integration

1. Navigate to **Settings \> System \> System Settings** from the DefectDojo sidebar. On instances still using the previous menu layout this sits under a group named after your license package — **Pro Settings** or **Enterprise Settings**. See [The Settings Menu](/navigation/pro__settings_menu/).
​
2. In the **Jira Integration Settings** section, check **Enable Jira Integration**.
​
3. Click **Submit**.  **Jira Instances** appears in the sidebar immediately, without reloading the page:

![image](images/jira-enable-system-settings-pro.png)

### What the setting controls

Enabling **Enable Jira Integration** is what makes the rest of the Jira interface appear.  With it turned on you get:

* the **Jira Instances** menu, where Jira Instances are added and edited
* the **Jira Project Settings** page on the Asset ⚙️ menu, and the Jira settings on Engagements
* the **Push to Jira** actions on Findings and Finding Groups, the Jira fields on the Finding and bulk edit forms, and the Jira columns on the Asset, Engagement, Finding and Finding Group lists (including CSV exports)

The setting also gates the integration outside the UI: while it is off, DefectDojo will not push Findings to Jira (including `push_to_jira` requests sent through the API), and incoming Jira webhooks are ignored.

The remaining Jira fields in **Jira Integration Settings** (**Add Vulnerability ID as Jira Label**, **Enable Jira Web Hook**, **Disable Jira Web Hook Secret**, **Jira Web Hook Secret**, **Jira Minimum Severity**) stay visible whether the integration is on or off, but they have no effect until it is enabled.

## Step 2: Connect a Jira Instance

With the integration enabled, connecting a Jira Instance is the next step in setting up DefectDojo's Jira integration.  Please note Jira Service Management is currently not supported.

#### Required information from Jira

Atlassian uses different ways of authentication between Jira Cloud and Jira Data Center.

for **Jira Cloud**, you will need:
* a Jira URL, i.e. https://yourcompany.atlassian.net/
* an account with permissions to create and update issues in your Jira instance.  This can be:
    * A standard **username / password** combination
    * A **username / API Token** combination

for **Jira Data Center (or Server)**, you will need:
* a Jira URL, i.e. https://jira.yourcompany.com
* an account with permissions to create and update issues in your Jira instance.  This can be:
    * A standard **username / password** combination
    * A **emailaddress / Personal Access Token** combination

Optionally, you can map:
* Jira Transitions to trigger Re-Opening and Closing Findings
* Jira Resolutions which can apply Risk Acceptance and False Positive statuses to Findings (optional)

Multiple Jira Spaces can be handled by a single Jira Instance connection, as long as the Jira account / token used by DefectDojo has permission to create Issues in the associated Jira Space.

### Add a Jira Instance

1. Make sure **Enable Jira Integration** is checked in System Settings, as described in [Step 1](#step-1-enable-the-jira-integration-in-system-settings).  The **Jira Instances** menu does not appear on the sidebar until it is.

2. Navigate to the  **Enterprise Settings \> Jira Instances \> + New Jira Instance**  page from the DefectDojo sidebar.

![image](images/jira-instance-beta.png)

3. Select a **Configuration Name** for this Jira Instance to use in DefectDojo. This name is simply a label for the Instance connection in DefectDojo, and does not need to be related to any Jira data.

4. Select the URL for your company's Jira instance \- likely similar to `https://**yourcompany**.atlassian.net` if you're using a Jira Cloud installation.

5. Enter an appropriate authentication method in the Username / Password fields for Jira:
    * For standard **username / password Jira authentication**, enter a Jira Username and corresponding Password in these fields.
    * For authentication with a **user's API token (Jira Cloud)** enter the Username with the corresponding **API token** in the password field.
    * For authentication with a Jira **Personal Access Token (aka PAT, used in Jira Data Center and Jira Server only)**, enter the PAT in the password field.  Username is not used for authentication with a Jira PAT, but the field is still required in this form, so you can use a placeholder value here to identify your PAT.

Note that the user associated with this connection must have permission to create Issues and access data in your Jira instance.

6. You will need to provide values for an Epic Name ID, Re-open Transition ID and Close Transition ID.  These values can be changed later.  While logged into Jira, you can access these values from the following URLs:
- **Epic Name ID**: visit `https://<YOUR JIRA URL>/rest/api/2/field` and search for Epic Name. Copy the number out of `number` and paste it here.  If you do not have an Epic Name ID associated with your Space in Jira (due to using a Team-Managed Space, for example), enter 0 on this field.
- **Re-open Transition ID**: visit `https://<YOUR JIRA URL>/rest/api/latest/issue/<ANY VALID ISSUE KEY>/transitions?expand-transitions.fields` to find the ID for your Jira instance. Paste it in the Reopen Transition ID field.
- **Close Transition ID**: Visit `https://<YOUR JIRA URL>/rest/api/latest/issue/<ANY VALID ISSUE KEY>/transitions?expand-transitions.fields` to find the ID for your Jira instance. Paste it in the Close Transition ID field.

7. Select the Default issue type which you want to create Issues as in Jira. The options for this are **Bug, Task, Story** and **Epic** (which are standard Jira issue types) as well as **Spike** and **Security**, which are custom issue types. If you have a different Issue Type which you want to use, please contact [support@defectdojo.com](mailto:support@defectdojo.com) for assistance.

8. Select your Issue Template, which will determine the Issue Description when Issues are created in Jira.

The two types are:
- **Jira\_full**, which will include all Finding information in Jira Issues
- **Jira\_limited**, which will include a smaller amount of Finding information and metadata.

If you leave this field blank, it will default to **Jira\_full.**  If you need a different kind of template, reach out to [support@defectdojo.com](mailto:support@defectdojo.com).

9. If you wish, enter the name of a Jira Resolution which will change the status of a Finding to Accepted or to False Positive (when the Resolution is triggered on the Issue).

The form can be submitted from here.  If you wish, you can further customize your Jira integration under Optional Fields.  Clicking this button will allow you to apply generic text to Jira Issues or change the mapping of Jira Severity Mappings.

## Step 3: Connect an Asset or Engagement to Jira

Each Asset or Engagement in DefectDojo has its own settings which govern how Findings are converted to JIRA Issues. From here, you can decide the associated Jira Space and set the default behaviour for creating Issues, Epics, Labels and other JIRA metadata.

### Add Jira to an Asset

You can find this page by clicking the Gear menu on an Asset ⚙️ and opening the **Jira Project Settings** page.

![image](images/jira-project-settings.png)

#### Jira Instance

If you have multiple instances of Jira set up, for separate Assets or teams within your organization, you can indicate which Jira Space you want DefectDojo to create Issues in. Select a Space from the drop\-down menu.

If this menu doesn't list any Jira instances, confirm that those Spaces are connected in your global Jira Configuration for DefectDojo \- yourcompany.defectdojo.com/jira.

#### Project key

This is the key of the Space that you want to use with DefectDojo.  The Space Key for a given Space can be found in the URL.  (This was previously referred to as a **Jira Project Key**, but as of September 2025, this is now referred to in Jira as the **Space Key**).

![image](images/Add_a_Connected_Jira_Project_to_a_Product_3.png)

#### Epic Issue Type Name

The name of the Epic issue type in Jira. This defaults to "Epic" but can be changed if your Jira instance uses a different name.

#### Issue template

Here you can determine how much DefectDojo metadata you want to send to Jira. Select one of two options:

* **jira\_full**: Issues will track all of the parameters from DefectDojo \- a full Description, CVE, Severity, etc. Useful if you need complete Finding context in Jira (for example, if someone is working on this Issue who doesn't have access to DefectDojo).

Here is an example of a **jira\_full** Issue:
​
![image](images/Add_a_Connected_Jira_Project_to_a_Product_4.png)

* **Jira\_limited:** Issues will only track the DefectDojo link, the Asset/Engagement/Test links, the Reporter and Environment fields. All other fields are tracked in DefectDojo only. Useful if you don't require full Finding context in Jira (for example, if someone is working on this Issue who mainly works in DefectDojo, and doesn't need the full picture in JIRA as well.)

​Here is an example of a **jira\_limited** Issue:

![image](images/Add_a_Connected_Jira_Project_to_a_Product_5.png)

#### Component

If you manage your Jira Space using Components, you can assign the appropriate Component for DefectDojo here. To assign more than one Component, enter a comma-separated list (for example, `Security, DevSecOps`); each value is sent to Jira as a separate component.

#### Custom fields

If you don't need to use Custom Fields with DefectDojo issues, you can leave this field as 'null'.

However, if your Jira Space Settings **require you** to use Custom Fields on new Issues, you will need to hard-code these mappings.

Note that DefectDojo cannot send any Issue\-specific metadata as Custom Fields, only a default value. This section should only be set up if your Jira Space **requires that these Custom Fields exist** in every Issue in your Space.

Follow **[this guide](#custom-fields-in-jira)** to get started working with Custom Fields.

#### Close / Reopen Transition fields

Some Jira workflows **require** certain fields to be set as part of a transition — for example, a workflow that refuses to close an Issue unless a Resolution and a Justification field are provided on the close screen. The Custom fields setting above only applies when an Issue is *created*, so it cannot satisfy these workflows.

Without these settings, DefectDojo sends close / reopen transitions with no fields. A workflow that requires fields will reject that transition, and the Finding and the Jira Issue fall out of sync: the Finding shows as Mitigated in DefectDojo while the Issue remains open in Jira.

The **Close Transition fields** and **Reopen Transition fields** settings accept a JSON object that is sent as the `fields` payload of the close / reopen transition call. For example, to close Issues with a Resolution of *Won't Fix* plus a justification value:

```json
{
    "resolution": {"name": "Won't Fix"},
    "customfield_10200": "Risk accepted by security team #report-false-positive"
}
```

Leave these settings as 'null' if your Jira workflow does not require fields on transitions.

**Which fields do you need?**

* Ask your Jira admin which fields are on the close / reopen **transition screens**, and which of them are enforced by a validator. The configured JSON must satisfy **every** required field: if any required field is missing from the payload, Jira rejects the whole transition and sets nothing — supplying only some of the required fields does not help.
* Conversely, fields must be present **on the transition screen** to be sent at all: Jira rejects transitions that attempt to set fields that are not on the screen for that transition.
* On workflows built with Jira Cloud's current workflow editor, Jira automatically fills in the site's default Resolution when an Issue moves to a done-category status.  So, a required Resolution alone will not block a bare transition there, and the practical use of `"resolution"` in this payload is choosing a *meaningful* value (for example *False Positive*) instead of the site default. Workflows built with the classic editor, or with marketplace validator apps, can still hard-require Resolution.
* Reopen transitions typically clear the Resolution via the workflow itself, so **Reopen Transition fields** usually only needs the custom fields your workflow requires.

**Notes:**

* The same JSON is sent for *every* close (or reopen) transition for the Asset or Engagement — the values are static and do not vary per Finding. If you need different fields per disposition (for example, a different Resolution for False Positive findings than for remediated findings), use the DefectDojo Pro Jira Integrator, which supports per-status transition field mappings.
* Values use the same format as Jira's REST API: strings for text fields, `{"name": ...}` for resolutions, `[{"name": ...}]` for multi-select fields, and so on.
* If transitions were rejected while these settings were missing or incomplete, correcting the settings repairs the drift: the next status push for the Finding retries the transition with the configured fields.
* Both settings are also available on the `/api/v2/jira_projects/` REST endpoint (`close_transition_fields` / `reopen_transition_fields`), so they can be managed via the API.
* These fields are also applied when DefectDojo closes an Issue because its Finding was **deleted** — the values are captured at the moment the close is queued.

#### Jira labels

Select the relevant labels that you want the Issue to be created with in Jira, e.g. **DefectDojo**, **YourProductName..**

![image](images/Add_a_Connected_Jira_Project_to_a_Product_6.png)

#### Default assignee

The name of the default assignee in Jira. If left blank, DefectDojo will follow the default behaviour in your Jira Space when creating Issues.

### Jira Project Settings

#### Enabled

This toggle controls whether DefectDojo pushes Findings to Jira for this Asset. Disabling this will not delete or change any existing Jira tickets created by DefectDojo, but will prevent any further updates or new Issue creation.

Jira integrations can be removed from your instance only if no related Issues have been created.  If Issues have been created, there is no way to completely remove a Jira Instance from DefectDojo.

#### Add Vulnerability Id as a Jira label

This allows you to add the Vulnerability ID data as a Jira Label automatically. Vulnerability IDs are added to Findings from individual security tools \- these may be Common Vulnerabilities and Exposures (CVE) IDs or a different format, specific to the tool reporting the Finding.

#### Push All Issues

If checked, DefectDojo will automatically push any Active and Verified Findings to Jira as Issues. If left unchecked, all Findings will need to be pushed to Jira manually (individually or via bulk push).

When this setting is enabled, Jira Issues will continue to sync with DefectDojo even if the Finding's status changes.

#### Enable Engagement Epic Mapping

In DefectDojo, Engagements represent a collection of work. Each Engagement contains one or more tests, which contain one or more Findings which need to be mitigated. Epics in Jira work in a similar way, and this checkbox allows you to push Engagements to Jira as Epics.

* An Engagement in DefectDojo \- note the three findings listed at the bottom.
​
![image](images/Add_a_Connected_Jira_Project_to_a_Product_8.png)
* How the same Engagement becomes an Epic when pushed to JIRA \- the Engagement's Findings are also pushed, and live inside the Engagement as Child Issues.

![image](images/Add_a_Connected_Jira_Project_to_a_Product_9.png)

#### Push Notes

If enabled, Jira comments will populate on the associated Finding in DefectDojo, under Notes, and vice versa; Notes on Findings will be added to the associated Jira Issue as Comments.

#### Send SLA Notifications As Comments

If enabled, any Issue which breaches DefectDojo's Service Level Agreement rules will have comments added to the Jira issue indicating this. These comments will be posted daily until the Issue is resolved.

Service Level Agreements can be configured under **Configuration \> SLA Configuration** in DefectDojo and assigned to each Asset.

#### Send Risk Acceptance Expiration Notifications As Comment

If enabled, any Issue where the associated DefectDojo Risk Acceptance expires will have a comment added to the Jira issue indicating this. These comments will be posted daily until the Issue is resolved.

### Engagement-Level Jira Settings

By default, Engagements **inherit Jira settings from their Asset**. However, you can override the Jira settings for individual Engagements.

To access Engagement-level Jira settings, click the Gear menu ⚙️ on an Engagement and open the **Jira Project Settings** page.

From here, you can uncheck **Inherit from Asset** and provide Engagement-specific values for: **Project Key**, **Issue Template, Custom Fields, Jira Labels, Default Assignee**, and other settings.

Note that once an Engagement has its own Jira project assigned, it can no longer inherit from the Asset.

![image](images/Creating_Issues_in_Jira_5.png)

## Step 4: Configure Bidirectional Sync: Jira Webhook

The Jira integration allows for bidirectional sync via webhook. DefectDojo receives Jira notifications at a unique address, which can allow for Jira comments to be received on Findings, or for Findings to be resolved via Jira depending on your configuration.

### Locating your Jira Webhook URL

Your Jira Webhook is located on the System Settings form under **Jira Integration Settings**: **Enterprise Settings \> System Settings** from the sidebar.

You also need to check **Enable Jira Web Hook** on the same page before DefectDojo will process incoming Jira notifications.  Incoming webhooks are ignored if either that box or **Enable Jira Integration** (see [Step 1](#step-1-enable-the-jira-integration-in-system-settings)) is unchecked.

![image](images/Configuring_the_Jira_DefectDojo_Webhook.png)

### Creating the Jira Webhook

1. Visit `**https:// \<YOUR JIRA URL\> /plugins/servlet/webhooks**`
2. Click 'Create a Webhook'.
3. For the field labeled 'URL' enter: `https:// \<**YOUR DOJO DOMAIN**\> /jira/webhook/ \<**YOUR GENERATED WEBHOOK SECRET**\>`. The Web Hook Secret is listed under the Jira Integration Settings as listed above.
4. Under 'Comments' enable 'Created'. Under Issue enable 'Updated'.
5. Make sure your JIRA instance trusts the SSL certificate used by your DefectDojo instance. For JIRA Cloud DefectDojo must use [a valid SSL/TLS certificate, signed by a globally trusted certificate authority](https://developer.atlassian.com/cloud/jira/platform/deprecation-notice-registering-webhooks-with-non-secure-urls/)

Note that you do not need to create a Secret within Jira to use this webhook. The Secret is built into DefectDojo's URL, so simply adding the complete URL to the Jira Webhook form is sufficient.

Incoming webhook requests are authenticated by the secret in that URL, so treat the full URL as a credential and keep it private.

#### Testing the Webhook

Once you have one or more Issues created from DefectDojo Findings, you can test the Webhook by adding a Comment to one of those Findings. The Comment should be received by the Jira webhook as a note.

If this doesn't work correctly, it could be due to a Firewall issue on your Jira instance blocking the Webhook.

* DefectDojo's Firewall Rules include a checkbox for **Jira Cloud,** which needs to be enabled before DefectDojo can receive Webhook messages from Jira.

### Alternative: Using Jira Automation (Send web request)

Some Jira instances don't allow system webhooks under `/plugins/servlet/webhooks` — for example, when that administration area is restricted and only **Jira Automation** rules are permitted. In that case you can drive the same bidirectional sync using Automation's **Send web request** action, which posts to the same DefectDojo webhook endpoint.

DefectDojo's webhook endpoint accepts any HTTP `POST` with `Content-Type: application/json` and a valid secret in the URL path. It does **not** require the request to originate from Jira's system webhook mechanism, so Automation's "Send web request" action works as a drop-in alternative.

#### Prerequisites

The same prerequisites as the system webhook apply:

* **Enable JIRA integration** and **Enable JIRA web hook** are both checked on the ⚙️ **Configuration \> System Settings** page.
* A non-empty **Jira webhook secret** is set on that page. The secret may only contain the characters `A-Z`, `a-z`, `0-9`, `_` and `-`.
* The Finding (or Finding Group) is already linked to the Jira issue. If the issue isn't linked to a DefectDojo Finding, the request is still accepted (HTTP `200`) but no action is taken.

#### How DefectDojo processes the request

* DefectDojo branches on a top-level `webhookEvent` field. Only `"jira:issue_updated"` and `"comment_created"` are processed; any other value is accepted and ignored. Automation does **not** add this field on its own, so you must include it in the request body yourself.
* Because of that, set the request **Body** to **Custom data** and supply the JSON below. The **Empty** and **Jira issue data** body options do not include the required `webhookEvent` field, so DefectDojo will ignore them.
* The endpoint always returns HTTP `200`, regardless of whether an update was applied. Success or failure is only visible in the response body and in the DefectDojo logs — a `200` in Automation's audit log does **not** by itself confirm the update reached a Finding.

#### Rule 1 — Issue updated

Create an Automation rule with:

* **Trigger:** *Issue transitioned* (or another trigger that fires when the fields you sync change, e.g. *Field value changed* on Status).
* **Action:** *Send web request*
  * **Web request URL:** `https://<YOUR DOJO DOMAIN>/jira/webhook/<YOUR WEBHOOK SECRET>`
  * **HTTP method:** `POST`
  * **Web request body:** *Custom data*
  * **Headers:** `Content-Type: application/json`
  * **Custom data:**

```json
{
  "webhookEvent": "jira:issue_updated",
  "issue": {
    "id": "{{issue.id}}",
    "fields": {
      "updated": "{{issue.updated}}",
      "resolution": null,
      "status": { "statusCategory": { "key": "{{issue.status.statusCategory.key}}" } },
      "assignee": { "name": "{{issue.assignee.accountId}}", "displayName": "{{issue.assignee.displayName}}" }
    }
  }
}
```

Constraints for issue updates:

* `issue.id` must be the **numeric internal Jira issue ID** (`{{issue.id}}`), not the issue key (e.g. `PROJ-123`). DefectDojo matches the update to a Finding by this numeric ID.
* The `resolution` and `updated` fields must always be present. `resolution` may be `null`, but if either field is missing the request is accepted (`200`) and silently not processed.
* Status sync and auto-mitigation are driven by `status.statusCategory.key`, whose Jira values are `new` (To Do), `indeterminate` (In Progress) and `done` (Done). A Finding is only mitigated when the issue is genuinely closed, not merely because a resolution value happens to be present.

#### Rule 2 — Issue commented

Create a second Automation rule with:

* **Trigger:** *Issue commented*
* **Action:** *Send web request* — same URL, method, header and *Custom data* body option as Rule 1, with this body:

```json
{
  "webhookEvent": "comment_created",
  "comment": {
    "self": "https://<your-jira-host>/rest/api/2/issue/{{issue.id}}/comment/{{comment.id}}",
    "body": "{{comment.body}}",
    "updateAuthor": { "name": "{{comment.author.accountId}}", "displayName": "{{comment.author.displayName}}" }
  }
}
```

Constraints for comments:

* Both `body` and `updateAuthor` must be present.
* DefectDojo derives the target issue from the `comment.self` URL — specifically the `<id>` in the `.../issue/<id>/comment/...` segment — so `{{issue.id}}` (the numeric ID) must appear there.
* **Loop prevention:** if the comment author matches the Jira account DefectDojo uses to post its own comments, DefectDojo skips the comment to avoid an echo loop. If you want *all* comments ingested, run the Automation rule as a **different** Jira user than the one configured in DefectDojo's Jira instance.

#### A note on smart values

The smart values shown above (`{{issue.id}}`, `{{issue.status.statusCategory.key}}`, `{{comment.author.accountId}}`, and so on) are the standard Jira Cloud names, but they can vary between instances. Before going live, use Automation's payload preview to confirm each smart value resolves to what you expect.

## Testing the Jira integration

#### Test 1: Do Findings successfully push to Jira?

In order to test that the Jira integration is working properly, you can add a new blank Finding to the Asset associated with Jira in DefectDojo. **Asset \> Findings \> Add New Finding.**

Add whatever title severity and description you wish, and then click "Finished". The Finding should appear as an Issue in Jira with all of the relevant metadata.

If Jira Issues are not being created correctly, check your Notifications for error codes.

* Confirm that the Jira User associated with DefectDojo's Jira Configuration has permission to create and update issues on that particular Jira Space.

#### Test 2: Jira Webhooks send to DefectDojo

In order to test the Jira webhooks, add a Note to a Finding which also exists in JIRA as an Issue (for example, the test issue in the section above).

If the webhooks are configured correctly, you should see the Note in Jira as a Comment on the issue.

If this doesn't work correctly, it could be due to a Firewall issue on your Jira instance blocking the Webhook.

* DefectDojo's Firewall Rules include a checkbox for **Jira Cloud,** which needs to be enabled before DefectDojo can receive Webhook messages from Jira.

## Disconnecting from Jira

Jira integrations can be removed from your instance only if no related Issues have been created.  If Issues have been created, there is no way to completely remove a Jira Instance from DefectDojo.

However, you can disable your Jira integration by disabling it at the Asset level.  From the **Jira Project Settings** page (accessible via the ⚙️ Gear menu on an Asset), uncheck the **Enabled** toggle.  This will not delete or change any existing Jira tickets created by DefectDojo, but will disable any further updates.

# Pushing Findings To Jira

An Asset with a JIRA mapping can push Findings to Jira as Issues using several methods.  You can push Findings individually, in bulk, as Finding Groups, or automatically.

## Push a Single Finding

1. Open the Finding you want to push.
2. Click the **☰ Finding Menu** and select **Push to Jira**.
3. Confirm the push when prompted. DefectDojo will create a Jira Issue and link it to the Finding.

Once the Issue is created, DefectDojo will display a link to the Jira Issue on the Finding page.

![image](images/Creating_Issues_in_Jira_2.png)

You can also check the **Push to Jira** checkbox when editing a Finding via the **Edit Finding** form. When the Finding is saved, it will be pushed to Jira.

### Updating a Linked Jira Issue

If a Finding already has a linked Jira Issue, selecting **Push to Jira** again will update the existing Jira Issue with any changes made in DefectDojo. If **Push All Issues** is enabled on the Asset, this syncing happens automatically.

### Unlinking a Finding from Jira

To remove the association between a Finding and its Jira Issue, click the **☰ Finding Menu** and select **Unlink From Jira**. This removes the link in DefectDojo but does not delete the Jira Issue itself.

## Bulk Push Findings

You can push multiple Findings to Jira at once using the Bulk Update form:

1. From a Findings list, select the Findings you want to push using the checkboxes.
2. Open the **Bulk Update** form.
3. Under **Jira Settings**, check the **Push to Jira** checkbox.
4. Click **Submit**.

The selected Findings will be queued for Jira push. DefectDojo will display a confirmation message indicating how many Findings were queued.

## Push Engagements as Epics

If **Enable Engagement Epic Mapping** is turned on in your Jira Project Settings, you can push an Engagement to Jira as an Epic. The Engagement's Findings will be pushed as Child Issues within that Epic.

To push an Engagement as an Epic:

1. Open the Engagement you want to push.
2. Click the **☰ Engagement Menu** and select **Push to Jira**.
3. Optionally, provide an **Epic Name** (defaults to the Engagement name if left blank) and an **Epic Priority**.
4. Check **Push to Jira (Create Epic)** and submit the form.

## Push Finding Groups as Jira Issues

If you have Finding Groups enabled, you can push a Group of Findings to Jira as a single Issue rather than separate Issues for each Finding.

To push a Finding Group:

1. Open the Finding Group.
2. Click the **☰ Finding Group Menu** and select **Push to Jira**, or check the **Push to Jira** checkbox when editing the Finding Group.

The Jira Issue associated with a Finding Group must be deleted directly from the Jira instance if removal is needed.

### Automatically Create and Push Finding Groups

With **Push All Issues** enabled on the Asset, and a **Group By** option selected on import:

As long as the Finding Groups are being created successfully, the Finding Group is what will automatically push to Jira as an Issue, not the individual Findings.

![image](images/Creating_Issues_in_Jira_4.png)

## Automatic Push Behaviour

DefectDojo can automatically push Findings and updates to Jira in several scenarios:

### Push All Issues

When the **Push All Issues** setting is enabled on an Asset's Jira Project Settings, DefectDojo will automatically create Jira Issues for all Active and Verified Findings. This includes Findings created via scan import. Once a Jira Issue is created, it will continue to sync with DefectDojo even if the Finding's status changes.

### Auto-Sync on Status Changes

When **Push All Issues** or the system-level **Finding Jira Sync** setting is enabled, DefectDojo will automatically update linked Jira Issues when certain actions are taken on Findings:

* **Request Review** \- A comment is added to the linked Jira Issue (or the Finding Group's Jira Issue if the Finding belongs to a group).
* **Clear Review** \- A comment is added to the linked Jira Issue.
* **Close Finding** \- The linked Jira Issue is updated to reflect the closure. If **Push Notes** is enabled, a comment is also added.

## Jira Comments and Notes

When **Push Notes** is enabled in the Jira Project Settings:

* If a comment is added to a Jira Issue, the same comment will be added to the Finding, under the **Notes** section.
* Likewise, if a Note is added to a Finding, the Note will be added to the Jira issue as a comment.

## Jira Status Changes

The Jira Instance configuration has entries for two Jira Transitions which will trigger a status change on a Finding.

* When the **'Close' Transition** is performed on Jira, the associated Finding will also Close, and become marked as **Inactive** and **Mitigated** on DefectDojo. DefectDojo will record this change on the Finding page under the **Mitigated By** heading.
​
![image](images/Creating_Issues_in_Jira_3.png)

* When the **'Reopen' Transition** is performed on the Jira Issue, the associated Finding will be set as **Active** on DefectDojo, and will lose its **Mitigated** status.

## Mapping Jira Resolutions to Risk Acceptance / False Positive

The Jira Instance configuration includes two optional fields that let you map a Jira **Resolution** to a DefectDojo Finding status:

* **Risk Accepted Finding Mapping Resolution** — when a Jira issue is closed with this Resolution, the linked Finding becomes Risk Accepted in DefectDojo.
* **False Positive Finding Mapping Resolution** — when a Jira issue is closed with this Resolution, the linked Finding becomes False Positive in DefectDojo.

### Status vs Resolution: A Common Point of Confusion

These fields map the Jira **Resolution**, not the Jira **Status**.  Status and Resolution are two independent Jira concepts: Status describes where the issue is in the workflow (Open, In Progress, Done), while Resolution describes how it was resolved (Fixed, Won't Do, Duplicate, False Positive, etc.).

### Prerequisite: A "Set issue resolution" post-function on the Jira workflow transition

Jira's workflow engine does not populate the Resolution field automatically.  Each transition that should close an issue with a specific Resolution needs a **Set issue resolution** post-function configured on the transition itself.  Without that post-function, the issue moves to the new Status but the Resolution stays blank, and DefectDojo's mapping has nothing to match against.

A Jira admin can add this post-function from **Project Settings → Workflows → (edit workflow) → (select the closing transition) → Post Functions → Add post function → Set issue resolution**.

# Custom Fields in Jira

<span style="background: rgba(243, 122, 78,0.5">DefectDojo does not currently support passing any Issue\-specific information into these Custom Fields \- these fields will need to be updated manually in Jira after the issue is created. Each Custom Field will only be created from DefectDojo with a default value.</span>

<span style="background: rgba(0, 207, 83, 0.44)"> Jira Cloud now allows you to create a default Custom Field value directly in\-app. [See Atlassian's documentation on Custom Fields](https://support.atlassian.com/jira-cloud-administration/docs/configure-a-custom-field/) for more information on how to configure this.</span>

DefectDojo's built\-in Jira Issue Types (**Bug, Task, Story** and **Epic)** are set up to work 'out of the box'. Data fields in DefectDojo will automatically map to the corresponding fields in Jira. By default, DefectDojo will assign Priority, Labels and a Reporter to any new Issue it creates.

Some Jira configurations require additional custom fields to be accounted for before an issue can be created. This process will allow you to account for these custom fields in your DefectDojo \-\> Jira integration, ensuring that issues are created successfully. These custom fields will be added to any API calls sent from DefectDojo to a linked Jira instance.

If you don't already use Custom Fields in Jira, there is no need to follow this process.

1. Recording the names of your Custom Fields in Jira (**Jira UI**)
2. Determine the Key values for the new Custom Fields (Jira Field Spec Endpoint)
3. Locate the acceptable data for each Custom Field, using the Key values as a reference (Jira Issue Endpoint)
4. Create a Field Reference JSON block to track all of the Custom Field Keys and acceptable data (Jira Issue Endpoint)
5. Store the JSON block in the associated DefectDojo Asset, to allow Custom Fields to be created from Jira (DefectDojo UI)
6. Test your work and ensure that all required data is flowing from Jira properly

#### Step 1: Record the names of your Custom Fields in Jira

Jira supports a variety of different Context Fields, including Date Pickers, Custom Labels, Radio Buttons. Each of these Context Fields will have a different Key value that can be found in the Jira API.

Write down the names of each required Custom Field, as you will need to search through the Jira API to find them in the next step.

**Example of a Custom Field list (your Custom Field names will be different):**

* DefectDojo Custom URL Field
* Another example of a Custom Field
* ...

#### Step 2: Finding your Jira Custom Field Key Values

Start this process by navigating to the Field Spec URL for your entire Jira instance.

Here is an example of a Field Spec URL:

`https://yourcompany-example.atlassian.net/rest/api/2/field`

The API will return a long string of JSON, which should be formatted into readable text (using a code editor, browser extension or <https://jsonformatter.org/>).

The JSON returned from this URL will contain all of your Jira custom fields, most of which are irrelevant to DefectDojo and have values of `"Null"`. Each object in this API response corresponds to a different field in Jira. You will need to search for the objects that have `"name"` attributes which match the names of each Custom Field you created in the Jira UI, and then note the value of their "key" attribute.

![image](images/Using_Custom_Fields.png)

Once you've found the matching object in the JSON output, you can determine the "key" value \- in this case, it's `customfield_10050`.

Jira generates different key values for each Custom Field, but these key values do not change once created. If you create another Custom Field in the future, it will have a new key value.

**Expanding our Custom Field list:**

* "DefectDojo Custom URL Field" \= customfield\_10050
* "Another example of a Custom Field" \= customfield\_12345
* ...

#### Step 3 \- Finding the Custom Fields on a Jira Issue

Locate an Issue in Jira that contains the Custom Fields which you recorded in Step 2\. Copy the Issue Key for the title (should look similar to "`EXAMPLE-123`") and navigate to the following URL:

`https://yourcompany-example.atlassian.net/rest/api/2/issue/EXAMPLE-123`

This will return another string of JSON.

As before, API output will contain lots of `customfield_##` object parameters with `null` values \- these are custom fields that Jira adds by default, which aren't relevant to this issue. It will also contain `customfield_##` values that match the Custom Field Key values that you found in the previous step. Unlike with the Field Spec output, you won't see names identifying any of these custom fields, which is why you needed to record the key values in Step 2\.

![image](images/Using_Custom_Fields_2.png)

**Example:**
We know that `customfield_10050` represents the DefectDojo Custom URL Field because we recorded it in Step 2\. We can now see that `customfield_10050` contains a value of `"https://google.com"` in the `EXAMPLE-123` issue.

#### Step 4 \- Creating a JSON Field Reference from each Jira Custom Field Key

You'll now need to take the value of each of the Custom Fields from your list and store them in a JSON object (to use as a reference). You can ignore any Custom Fields that don't correspond to your list.

This JSON object will contain all of the default values for new Jira Issues. We recommend using names that are easy for your team to recognize as 'default' values that need to be changed: '`change-me.com`', '`Change this paragraph.`' etc.

**Example:**

From step 3, we now know that Jira expects a URL string for "`customfield_10050`". We can use this to build our example JSON object.

Say we had also located a DefectDojo\-related short text field, which we identified as "`customfield_67890`". We would look at this field in our second API output, look at the associated value, and reference the stored value in our example JSON object as well.
​
Your JSON object will start to look like this as you add more Custom Fields to it.

```
{
	"customfield_10050": "https://change-me.com",
	"customfield_67890": "This is the short text custom field."
}
```

Repeat this process until all of the DefectDojo\-relevant custom fields from Jira have been added to your JSON Field Reference.

#### Data types \& Jira Syntax

Some fields, such as Date fields, may relate to multiple custom fields in Jira. If that is the case, you'll need to add both fields to your JSON Field Reference.

```
  "customfield_10040": "1970-01-01",
  "customfield_10041": "1970-01-01T03:30:00.000+0200",
```

Other fields, such as the Label field, may be tracked as a list of strings \- please make sure your JSON Field Reference uses a format that matches API output from Jira.

```
// a list of custom labels on a Jira object
  "customfield_10042": [
    "custom-label-one",
    "this-is-default",
    "change-me-please"
  ],
```

Other custom fields may contain additional, contextual information that should be removed from the Field Reference. For example, the Custom Multichoice Field contains an extra block in the API output, which you'll need to remove, as this block stores the current value of the field.

* you should remove the extra object from this field:

```
"customfield_10047": [
    {
      "value": "A"
    },
    {
      "self": "example.url...",
      "value": "C",
      "id": "example ID"
    }
]
```
* instead, you can shorten this to the following and disregard the second part:

```
"customfield_10047": [
   {
      "value": "A"
   }
]
```

#### Example Completed Field Reference

Here is a complete JSON Field Reference, with in\-line comments explaining what each custom field pertains to. This is meant as an all\-encompassing example. Your JSON will contain different key values and data points depending on the Custom Values you want to use during issue creation.

```
{
  "customfield_10050": "https://change-me.com",

  "customfield_10049": "This is a short text custom field",

// two different fields, but both correspond to the same custom date attribute
  "customfield_10040": "1970-01-01",
  "customfield_10041": "1970-01-01T03:30:00.000+0200",

// a list of custom labels on a Jira object
  "customfield_10042": [
    "custom-label-one",
    "this-is-default",
    "change-me-please"
  ],

// custom number field
  "customfield_10043": 0,

// custom paragraph field
  "customfield_10044": "This is a very long winded way to say CHANGE ME PLEASE",

// custom radio button field
  "customfield_10045": {
    "value": "radio button option"
  },

// custom multichoice field
  "customfield_10047": [
    {
      "value": "A"
    }
  ],

// custom checkbox field
  "customfield_10039": [
    {
      "value": "A"
    }
  ],

// custom select list (singlechoice) field
  "customfield_10048": {
    "value": "1"
  }
}
```

#### Step 5 \- Adding the Custom Fields to a DefectDojo Asset

You can now add these custom fields to the associated DefectDojo Asset, in the Jira Project Settings page (accessible via the ⚙️ Gear menu on the Asset). Paste the JSON Field Reference as plain text in the **Custom Fields** box and save.

#### Step 6 \- Testing your Jira Custom Fields from a new Finding:

Now, when you create a new Finding in the Jira\-associated Asset, Jira will automatically create all of these Custom Fields in Jira according to the JSON block contained within. These Custom Fields will be created with the default ("change\-me\-please", etc.) values.

Within the Asset on DefectDojo, navigate to the Findings \> Add New Finding page. Make sure the Finding is both Active and Verified to ensure that it pushes to Jira, and then confirm on the Jira side that the Custom Fields are successfully created without any inconsistencies.
