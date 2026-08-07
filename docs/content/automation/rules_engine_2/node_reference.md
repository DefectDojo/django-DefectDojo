---
title: "Node Reference"
description: "Every node Rules Engine 2.0 ships with, and what each one does"
weight: 3
audience: pro
aliases:
  - /automation/rules_engine_v2/node_reference/
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Rules Engine 2.0 is a DefectDojo Pro-only feature.</span>

Rules Engine 2.0 ships 25 nodes in four categories. This page documents all of them.

Unless stated otherwise, a node takes one input, produces one output called `out`, and passes every item it received on to that output. That matters when you chain nodes: a Findings node changes the Finding and then hands the item onward, so several of them in a row all apply.

## Triggers

Every graph has exactly one trigger, and only a trigger can start a run. All three produce Finding items and all three take a **Scope** that narrows which Findings they produce. See [Building Rules](../building_rules/) for how scope works.

### On Finding Event

`trigger.finding`

Runs when Findings are created, updated, closed or reopened.

| Setting | Default | Notes |
|---------|---------|-------|
| **Event** | `created` | Which Finding change wakes this rule: `created`, `updated`, `closed`, `reopened`, or `any` for all four. |
| **Scope** | empty | Which Findings this rule considers. Empty means every Finding the rule owner can see. |

Findings named by the event are matched against scope before they enter the graph, so the event decides *when* and scope decides *which*.

### On a Schedule

`trigger.schedule`

Sweeps every Finding in scope on a schedule. The schedule is configured on the rule and is limited to quarter-hour marks.

| Setting | Default | Notes |
|---------|---------|-------|
| **Scope** | empty | Which Findings this rule considers. |

### Manual Run

`trigger.manual`

Sweeps every Finding in scope when you press **Run** on the rule.

| Setting | Default | Notes |
|---------|---------|-------|
| **Scope** | empty | Which Findings this rule considers. |

## Logic

### If / Filter

`filter.if`

Routes each item down the **true** or the **false** branch, by conditions. This is the only node with two outputs, and it is how a graph branches.

| Setting | Default | Notes |
|---------|---------|-------|
| **Conditions** | empty | Each row is a path, an operator and a value. See [Conditions](../building_rules/#conditions). |
| **Match** | `all` | Whether every condition has to hold (`all`), or just one of them (`any`). |

An empty condition list passes everything down the true branch. Both branches are optional: leaving the false branch unwired simply drops the items that failed.

### Limit

`flow.limit`

Passes the first N items and drops the rest. Useful as a safety valve while you are testing a rule, and for capping how many tickets or messages a single run can produce.

| Setting | Default | Notes |
|---------|---------|-------|
| **Keep First** | `100` | How many items to pass on. |

### De-duplicate Within Run

`flow.dedupe_batch`

Keeps the first item per key and drops later ones carrying the same key. Scoped to the run, so it de-duplicates within one execution and not across executions.

| Setting | Default | Notes |
|---------|---------|-------|
| **Key Path** | `finding.hash_code` | The item path whose value identifies a duplicate. |

A common use is `finding.component_name`, to notify once per affected component instead of once per Finding.

## Findings

These nodes change Findings. Every change is attributed back to the rule, run and node that made it, and shows up on the Finding's provenance timeline.

### Set Severity

`finding.set_severity`

Sets the severity, and recomputes the SLA date and priority with it.

| Setting | Options |
|---------|---------|
| **Severity** | `Critical`, `High`, `Medium`, `Low`, `Info` |

### Set a Field

`finding.set_field`

Sets, appends to, or prepends to a text field.

| Setting | Default | Notes |
|---------|---------|-------|
| **Field** | none | One of `component_name`, `component_version`, `cvssv3`, `cwe`, `description`, `file_path`, `impact`, `mitigation`, `service`, `title`. |
| **Mode** | `set` | `set`, `append` or `prepend`. A CVSSv3 vector can only be replaced. |
| **Value** | none | The text to write. Supports `{{finding.title}}` style placeholders. |

### Set Status

`finding.set_status`

Moves the Finding to a status.

| Setting | Default | Notes |
|---------|---------|-------|
| **Status** | none | `active`, `inactive`, `verified`, `unverified`, `false_positive`, `mitigated`, `reopen`. |
| **Note** | empty | An optional note recorded alongside the status change. |

### Add Tags

`finding.add_tags`

Adds tags to the Finding. Existing tags are kept.

| Setting | Notes |
|---------|-------|
| **Tags** | Comma separated. Supports `{{product.name}}` style placeholders, so you can tag with data from the Finding. |

### Add a Note

`finding.add_note`

Adds a note to the Finding.

| Setting | Notes |
|---------|-------|
| **Note** | The note text. Supports placeholders. |

### Set Owners

`finding.set_owners`

Makes a group responsible for the Finding.

| Setting | Notes |
|---------|-------|
| **Group** | The group that owns these Findings. |

### Set Reviewers

`finding.set_reviewers`

Puts the Finding under review by the selected users.

| Setting | Notes |
|---------|-------|
| **Reviewers** | One or more users who should review these Findings. |

### Accept Risk

`finding.risk_accept`

Simple risk accepts the Finding, or adds it to a risk acceptance record.

| Setting | Default | Notes |
|---------|---------|-------|
| **How** | `simple` | `simple` sets simple risk acceptance on the Finding. `acceptance` adds it to a risk acceptance record. |
| **Accepted** | on | Shown for `simple`. Turn off to un-accept the risk. |
| **Risk Acceptance** | none | Shown for `acceptance`. Which risk acceptance to add these Findings to. |

### Set Mitigation Policy

`finding.set_mitigation_policy`

Sets the mitigation policy the Finding is remediated under.

| Setting | Notes |
|---------|-------|
| **Mitigation Policy** | The policy to apply. |

### Change Priority

`finding.set_priority`

Sets the priority, or adjusts it arithmetically. This overrides the calculated priority.

| Setting | Default | Notes |
|---------|---------|-------|
| **Operation** | `set` | `set`, `add`, `subtract`, `multiply`, `divide`. |
| **Value** | none | The priority to set, or the amount to adjust by. |

### Set Risk

`finding.set_risk`

Sets the risk, overriding the computed one.

| Setting | Options |
|---------|---------|
| **Risk** | `Low`, `Medium`, `Needs Action`, `Urgent` |

## Egress

Egress nodes are the nodes that leave DefectDojo. Every one of them records a [Delivery](../deliveries/) before anything is sent, and every one of them honours the rule's **Simulate** or **Live** mode.

Several of them offer the same **One Message per Finding** choice. Off, the node sends one message describing the whole batch, with a severity breakdown and a capped list of Findings. On, it sends one message per Finding.

A node sending one message per Finding stops after 1,000 sends in a single run by default, and records a visible skip saying how many Findings it did not send about. See [Configuration](../configuration/#per-finding-send-ceiling).

### When a channel is unavailable

An egress node depends on something outside the rule: a Slack token, a Microsoft Teams webhook, a JIRA configuration, a licensed connector. When that is missing or switched off, the node cannot work, and Rules Engine 2.0 says so at three different moments rather than failing quietly:

* **In the palette**, an unavailable node is marked as such, with the reason, before you drag it onto the canvas.
* **On save**, a graph containing an unavailable node is refused. That is the moment somebody is present to pick a different one.
* **At run time**, the delivery is **skipped** with the reason attached, not failed. A rule saved while Slack was on should not start erroring the day somebody turns Slack off. The honest record is a skipped delivery saying Slack is off.

### Create a JIRA Issue

`ticket.jira`

Creates or updates the JIRA issue for the Finding.

| Setting | Default | Notes |
|---------|---------|-------|
| **Skip Findings That Already Have an Issue** | on | Leaves Findings that already have a JIRA issue alone. |
| **Update an Existing Issue** | off | Shown when the skip above is off. Pushes Findings that already have an issue, so JIRA is updated. |

The summary, description and priority come from the product's JIRA configuration, not from this node. A ticket a rule creates is therefore identical to one created by push all issues.

### Create a Downstream Ticket

`ticket.downstream`

Creates or updates a ticket through a [Downstream Connector](/connectors/downstream/about/).

| Setting | Default | Notes |
|---------|---------|-------|
| **Issue Trackers** | `auto` | `auto` uses the issue trackers assigned to the engagement or product. `mapping` targets one specific mapping. |
| **Issue Tracker Mapping** | none | Shown for `mapping`. Which mapping to push to. |
| **Operation** | `create` | `create` a ticket, or `update` the one that exists. An update with no existing ticket creates it. |
| **Skip Findings That Already Have a Ticket** | on | Leaves Findings that already have a ticket in the target mapping alone. |

The rule replaces the assignment's automatic push settings: severity and active-only filters are not applied a second time here. A Finding whose ticket already exists is skipped however that ticket was created.

### Send a Slack Message

`notify.slack`

Posts to a Slack channel using the system Slack token from **System Settings**.

| Setting | Default | Notes |
|---------|---------|-------|
| **Channel** | empty | For example `#appsec`. Empty uses the channel from system settings. |
| **One Message per Finding** | off | Off sends one message about the batch. |
| **Message** | `{{finding.severity}}: {{finding.title}} ({{product.name}})` | Rendered per Finding. |
| **Findings Listed in the Digest** | `10` | Shown for batch messages. How many Findings the message lists before it says how many more there were. |

### Send a Microsoft Teams Message

`notify.msteams`

Posts a card to the Microsoft Teams webhook configured in **System Settings**.

| Setting | Default | Notes |
|---------|---------|-------|
| **One Message per Finding** | off | Off sends one card about the batch. |
| **Message** | `{{finding.severity}}: {{finding.title}} ({{product.name}})` | Rendered per Finding. |
| **Findings Listed in the Digest** | `10` | Shown for batch messages. |

### Send an Email

`notify.email`

Emails a fixed list of addresses.

| Setting | Default | Notes |
|---------|---------|-------|
| **To** | none | One or more addresses, comma separated. Required. |
| **Subject** | `[DefectDojo] {{ctx.count}} finding(s) from rule {{ctx.rule_name}}` | Rendered once per message. |
| **Body** | an HTML body containing `{{ctx.findings_html}}` | HTML. `{{ctx.findings_html}}` renders the Finding list. |
| **One Message per Finding** | off | Off sends one email about the batch. |
| **Findings Listed in the Body** | `25` | How many Findings `{{ctx.findings_html}}` lists before it says how many more there were. |

### Call a Webhook

`notify.webhook`

POSTs JSON to a webhook endpoint.

| Setting | Default | Notes |
|---------|---------|-------|
| **Webhook Endpoint** | none | A configured [notification webhook](/automation/api/notification_webhooks/). Its custom header is sent with the request. |
| **URL** | empty | Shown when no endpoint is selected. Where to POST. |
| | | One of the two above is required. |
| **Signing Secret** | empty | Signs the body as `X-DefectDojo-Signature: sha256=HMAC`. |
| **One Message per Finding** | off | Off posts the whole batch in one request. |

Two things to know. A signing secret typed here is stored with the rule, so for anything sensitive prefer a configured endpoint and its own header. And a webhook called by a rule never changes that endpoint's own health status, so a rule cannot disable your notification webhooks by failing.

Free-text URLs are validated when you save. See [Configuration](../configuration/#outbound-destination-validation) for what is rejected and how to allow private addresses.

### Raise an In-App Alert

`notify.alert`

Creates an in-app alert about the batch.

| Setting | Default | Notes |
|---------|---------|-------|
| **Title** | `Rules Engine 2.0: {{ctx.rule_name}}` | Rendered once for the whole batch. |
| **Description** | `{{ctx.count}} finding(s) matched the rule {{ctx.rule_name}}.` | Rendered once for the whole batch. |
| **Recipients** | empty | Usernames, comma separated. Empty alerts the administrators. |

Recipients still control this through their own **Rules Engine Match** notification setting, so an alert cannot bypass a user's notification preferences.

### Generate a Report

`report.generate`

Generates a report from a template, scoped to the Findings that reached this node, and can announce the download link.

| Setting | Default | Notes |
|---------|---------|-------|
| **Report Template** | none | Which template to generate from. Required. |
| **Format** | `pdf` | `pdf` or `html`. |
| **Findings Included** | `batch_findings` | `batch_findings` limits the report to the Findings that reached this node. `template_default` lets the template use its own filters. |
| **Announce the Report** | `none` | `none`, `email` or `slack`. Sends the download link once the report is generated. |
| **Announce To** | empty | Shown when announcing. A Slack channel, or comma separated email addresses. Slack falls back to system settings. |
| **Announcement** | `Report ready: {{ctx.report_url}}` | Shown when announcing. `{{ctx.report_url}}` is the download link. |

`batch_findings` is what a rule can do that a scheduled report cannot: report on exactly the Findings that just matched.

The announcement is recorded as its own delivery, separate from the report generation, so you can see the report succeed and the announcement fail independently.
