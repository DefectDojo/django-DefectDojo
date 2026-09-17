---
title: "Node Reference"
description: "Every node Triage Engine ships with, and what each one does"
weight: 3
audience: pro
aliases:
  - /automation/rules_engine_v2/node_reference/
  - /automation/rules_engine_2/node_reference/
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Triage Engine is a DefectDojo Pro-only feature.</span>

Triage Engine ships 43 nodes in five categories. This page documents all of them.

Unless stated otherwise, a node takes one input, produces one output called `out`, and passes every item it received on to that output. That matters when you chain nodes: a Findings node changes the Finding and then hands the item onward, so several of them in a row all apply.

## Triggers

Every graph has exactly one trigger, and only a trigger can start a run. The trigger also decides what kind of item the rule works on: Findings or Assets (Products). Most triggers take a **Scope** that narrows what they produce — see [Building Rules](../building_rules/) for how scope and the kind of item work. **On a Missing Scan** is the exception: it fires on something *not* happening, so it takes no scope, and it reports assets rather than Findings.

### On Finding Event

`trigger.finding`

Runs when Findings are created, updated, closed or reopened.

| Setting | Default | Notes |
|---------|---------|-------|
| **Event** | `created` | Which Finding change wakes this rule: `created`, `updated`, `closed`, `reopened`, or `any` for all four. |
| **Scope** | empty | Which Findings this rule considers. Empty means every Finding the rule owner can see. |

Findings named by the event are matched against scope before they enter the graph, so the event decides *when* and scope decides *which*.

### On Asset Event

`trigger.asset`

Runs when Assets (Products) are created or updated. Tag changes count as updates, so a rule can react to an Asset being tagged.

| Setting | Default | Notes |
|---------|---------|-------|
| **Event** | `created` | Which Asset change wakes this rule: `created`, `updated`, or `any` for both. |
| **Scope** | empty | Which Assets this rule considers, in the Assets list's own filters. Empty means every Asset the rule owner can see. |

Assets named by the event are matched against scope before they enter the graph. For an update, the names of the changed fields travel with the items as `ctx.changed_fields`, so an If / Filter node can say "only when the organization changed" (`ctx.changed_fields` `contains` `organization`) or "only when tagged" (`contains` `tags`).

### On a Schedule

`trigger.schedule`

Sweeps everything in scope on a schedule. The schedule is configured on the rule and is limited to quarter-hour marks.

| Setting | Default | Notes |
|---------|---------|-------|
| **Sweep Over** | `Findings` | What kind of item this rule sweeps: `Findings` or `Assets`. The trigger decides what every node downstream works on. |
| **Scope** | empty | What this rule considers. Follows Sweep Over: a Finding sweep filters in the Findings list's vocabulary, an Asset sweep in the Assets list's. |

### Manual Run

`trigger.manual`

Sweeps everything in scope when you press **Run** on the rule.

| Setting | Default | Notes |
|---------|---------|-------|
| **Sweep Over** | `Findings` | What kind of item this rule sweeps: `Findings` or `Assets`. The trigger decides what every node downstream works on. |
| **Scope** | empty | What this rule considers. Follows Sweep Over: a Finding sweep filters in the Findings list's vocabulary, an Asset sweep in the Assets list's. |

### On a Missing Scan

`trigger.scan_absence`

Runs on a schedule and reports assets whose expected scan has **not** arrived. This is the only trigger that fires on something *not* happening, which is why it is also the only one that does not take a scope: a scan that never arrived produces no Finding to filter.

| Setting | Default | Notes |
|---------|---------|-------|
| **Expected within (days)** | `3` | An asset whose latest import of the scan type is older than this is reported. FedRAMP Class C cadences: 3 days for machine-based resources, 14 for resources likely to drift, 30 otherwise. |
| **Scan types** | empty | Scan types to expect, as a list of names. Empty checks every scan type the asset has already received. |
| **Assets** | empty | Asset ids to check. Empty checks every asset. |

**Name the scan types you expect.** Left empty, the node checks only the types an asset has already imported — which catches a scanner that stopped, but cannot catch one that was never wired up, because there is nothing to infer it from. Naming them explicitly catches both.

It emits **one item per asset and scan type**, not per Finding. An asset importing SAST daily and DAST never is failing its DAST cadence, and reporting per-asset would hide that behind the healthy scanner. An asset and scan type that has *never* imported is reported too, and sorts above any dated breach.

### What a missing-scan item looks like

These items have no Finding, so `finding.*` paths are all empty. The asset and the expected scan type are carried in their usual places, which means message templates written for Findings keep working:

```
product.name          the asset the scan was expected for
test.scan_type        the scan type that did not arrive
```

The absence specifics are on `ctx`:

```
ctx.scan_type                 the scan type that did not arrive
ctx.last_import               when it last arrived, or empty if it never has
ctx.days_overdue              days past the expected interval, 0 when never imported
ctx.expected_interval_days    the interval that was expected
ctx.never_imported            true when this asset has never received this scan type
```

Wire these into **Egress** nodes — a Slack message, an email, a JIRA issue, a batched digest. Wiring them into a **Findings** node is harmless but pointless: there is no Finding to change, so the node does nothing.

### When a Scan Has Landed

`trigger.import`

Runs once for each scan import that finishes, or fails, on an asset in scope. Every way a scan reaches DefectDojo counts: an upload in the UI, an import or reimport through the API, a background import, and a connector sync (one event for the whole sync, however many chunks carried it). The trigger fires after the import has finished writing: findings persisted, old findings closed, import history recorded, post-processing run.

| Setting | Default | Notes |
|---------|---------|-------|
| **Event** | `completed` | `completed`, `failed`, or either. A failed import is one that raised before or while writing; a parser error counts, and it is announced even when no test was created. |
| **Scope** | empty | Which assets this rule watches imports on, in the Assets list's vocabulary. Empty is every asset the rule owner can see. |
| **Engagements** | empty | Narrow to imports into these engagements. Empty watches every engagement of the assets in scope. |
| **Scan Types** | empty | Scan type names to react to, as a list. Empty reacts to every scan type. |

It emits **one item per import**. The item has no Finding (every `finding.*` path is empty), and carries the test, engagement and asset in their usual places, so templates written for Findings keep working. The import specifics are on `ctx`:

```
ctx.import_outcome        success, empty (the report carried no findings), or failed
ctx.import_kind           import, reimport, or connector_sync
ctx.import_error          the failure message, for a failed import
ctx.findings_created      findings the import created
ctx.findings_closed       findings it closed
ctx.findings_reactivated  findings it reactivated
ctx.findings_untouched    findings it left as they were
ctx.build_id              the build id the import was submitted with, if any
ctx.commit_hash           the commit, if any
ctx.branch_tag            the branch or tag, if any
ctx.version               the version, if any
ctx.test_ids              the test the import wrote, for the report node's "triggering imports" scope
```

### When a Group of Scans Has Landed

`trigger.import_group`

Waits for a set of scan types to finish importing into an asset, then fires **once** for the whole group. It has two outputs: `complete` when every expected scan arrived, `incomplete` when the group gave up with scans still missing or failed. Wire the action for a finished pipeline (typically **Generate a Report**) to `complete`, and whatever should happen when the pipeline did not finish (an email naming the missing scans, or nothing) to `incomplete`.

A group is three separate decisions, and the settings keep them apart: **which scans make up the group**, **which arrivals belong together**, and **when it is safe to act**.

| Setting | Default | Notes |
|---------|---------|-------|
| **Scope** | empty | Which assets this rule watches, in the Assets list's vocabulary. Each asset waits for its own group. |
| **Engagements** | empty | Narrow to these engagements. When set, each engagement waits for its own group instead of the asset as a whole. |
| **Expected Scans** | `The scan types listed below` | Or `Every scan type seen recently`: the group is whatever scan types the asset has received within the lookback. That finds a scanner that stopped, but cannot find one that was never wired up. |
| **Scan Types** | empty | The group, as a list of scan type names. A member may instead be an object `{"scan_type": "ZAP Scan", "required": false, "on_failure": "count_as_arrived"}` to make it optional or give it its own failure policy. |
| **Lookback (days)** | `30` | Shown for **Every scan type seen recently**. How far back to look for the scan types the asset receives. |
| **Group Imports By** | `Arrival time only` | With a key (`Build ID`, `Commit hash`, `Branch or tag`, or `A test tag`), imports sharing the same value wait together and different values wait separately. Without one, the first arrival opens the group and later arrivals of missing scan types join it. |
| **Tag Prefix** | empty | Shown for **A test tag**. Only test tags starting with this correlate, for example `pipeline:`. |
| **Gives Up** | `After the maximum wait` | Or `At each tick of this rule's schedule`: every tick closes whatever is open, incomplete if scans are still missing. The schedule option needs a schedule on the rule. |
| **Maximum Wait (minutes)** | `1440` | Shown for **After the maximum wait**. How long after the first arrival the group waits for the rest before firing `incomplete`. Set it a little longer than the slowest scanner takes to report. |
| **Settle (minutes)** | `2` | A quiet period after the last expected scan lands before the rule fires, so a report is not built while that import is still being deduplicated. Zero fires as soon as the last scan lands. |
| **When a Scan Fails** | `Keep waiting for the deadline` | What a failed import of an expected scan type does to the group. See below. |

**How a group waits.** The first expected scan to land opens a *cycle* for its asset (and engagement, when narrowed; and correlation key, when grouping by one). Each further expected scan is recorded in that cycle; a scan type that lands twice keeps the latest import, so an hourly scanner and a daily one in the same group produce "the latest hourly result at the moment the daily one landed". When every required scan has arrived and the settle delay has passed, the cycle closes `complete`. When the maximum wait passes first, or the rule's schedule ticks (for **At each tick of this rule's schedule**), it closes `incomplete`. A scan landing after the cycle closed opens the next one. Pressing **Run** on the rule closes every open cycle as it stands, which is how you fire a group that is never going to complete.

**When a scan fails.** A failed import of an expected scan type is recorded against the cycle, and what happens next is the policy:

| Policy | Effect |
|--------|--------|
| **Keep waiting for the deadline** | The failure is recorded and the group keeps waiting. A retry that lands replaces it. At the deadline the rule fires `incomplete`, and the items say which scans failed and which never came. |
| **Fire incomplete immediately** | The cycle closes `incomplete` the moment a scan fails. |
| **Count it as arrived** | The failed scan satisfies the group; the cycle can complete, and the items still say which scan failed. |

A member listed as an object may override the rule's policy for itself. An optional member (`"required": false`) never blocks completion and never triggers a failure policy; it is simply included if it arrives.

**What the items look like.** The rule fires with **one item per expected scan type**, arrived or not. Like a missing-scan item, each has an empty Finding block; the test, engagement and asset are filled in for scans that arrived and empty for scans that did not. Every item carries the whole cycle on `ctx`, so a template on any of them can describe the group:

```
ctx.cycle_status        complete or incomplete
ctx.import_summary      one line, for example "3 of 4 feeds arrived; missing: ZAP Scan"
ctx.expected_count      how many scan types the group expects
ctx.arrived_count       how many arrived
ctx.missing_count       how many never came
ctx.failed_count        how many failed
ctx.arrived_members     the scan types that arrived, as a list
ctx.missing_members     the scan types that never came
ctx.failed_members      the scan types whose import failed
ctx.test_ids            the tests the arrived scans wrote
ctx.member_scan_type    this item's scan type
ctx.member_status       this item's scan: arrived, failed, or missing
ctx.member_outcome      success, empty, or failed, when it arrived
ctx.findings_created    finding counts of this item's import, as on When a Scan Has Landed
```

Two egress settings are built for these items. **Generate a Report** has a **Findings Included** option, `Findings of the Triggering Imports`, that reports on every Finding of the tests the group wrote, however many there are. **Send an Email** offers `{{ctx.imports_html}}`, a list of the group's scans and how each one ended, and `{{ctx.import_summary}}` renders in any template, including the report node's announcement.

The shipped template **Report when a group of scans has landed** wires all of this: the group trigger, a report on `complete`, and an email naming the missing scans on `incomplete`.

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
| **Accept Without Review Up To** | No limit | The most severe Finding this rule may accept on its own. Anything more severe is **not** accepted. |

#### Limiting what a rule may accept on its own

A rule that can accept risk can accept a Critical, and by default nothing says otherwise. *Accept
Without Review Up To* draws that line.

Findings over the limit are not dropped — the rule matched them for a reason. With
[Risk Acceptances 2.0](/triage_findings/findings_workflows/pro__risk_acceptance/) enabled they
are put into a Risk Acceptance **awaiting review**, named for the rule that asked and carrying why,
so a person decides. They stay active and counted the whole time. With that feature off there is no
review state to use, so they are simply left alone — never accepted, which is the point of the
limit. A rule preview creates nothing, as with every other action.

Two behaviours worth knowing: a severity the rule cannot recognise counts as *over* the limit (if it
cannot be ranked it cannot be called safe), while a *limit* that cannot be recognised is ignored
rather than blocking everything, because a rule that silently stops working is harder to notice than
one that keeps going.

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

### Set Potential Agency Impact (PAIN)

`finding.set_pain`

Assigns the FedRAMP Potential Agency Impact (PAIN) rating. When PAIN tiering is enabled on the Asset's SLA configuration, this rating drives the VDR remediation deadline. See [PAIN ratings](/federal_compliance/pain_ratings/) for how the rating feeds remediation timelines.

| Setting | Options |
|---------|---------|
| **PAIN rating** | `N1 - minimal customer effect`, `N2 - narrow customer effect`, `N3 - disruptive effect on one agency`, `N4 - debilitating on one agency, or disruptive on several`, `N5 - debilitating effect on more than one agency` |

The options carry FedRAMP's own customer-effect wording rather than the bare `N1`–`N5` codes, so a rule author judges the effect rather than a number.

### Set a Custom Field

`finding.set_custom_field`

Writes one of this instance's [Custom Fields](/asset_modelling/pro__custom_fields/) on the Finding. Offered only while Custom Fields is enabled, with one value control per field an administrator has defined for Findings.

| Setting | Notes |
|---------|-------|
| **Field** | Which custom field to write. |
| **Value** | Typed to the field: text takes a template with `{{finding.title}}` style placeholders, numbers take a number, dates take a `YYYY-MM-DD` date, booleans take true or false, and the select types offer the field's own options. |

The value is checked against the field's current definition when the rule is saved and again on every run, so a rule can never write a value the field's data type refuses. A text template that renders empty for a Finding leaves that Finding untouched (removal is the Clear node's job), setting a multi-select replaces the whole stored list, and Findings already holding the value are left alone.

Three behaviours worth knowing:

* **Scope is the boundary.** Like every Findings node, the write applies to every Finding the trigger produced under the rule owner's visibility.
* **A custom field write is not a Finding save.** Nothing that follows a Finding save runs: no SLA recomputation, no deduplication, no re-prioritization. A custom field edited by hand on a Finding's page does not wake **On Finding Event** rules either. A write made by a rule does cascade: other rules see it as an `updated` event, and later nodes in the same run read the new value.
* **The field must still exist.** If the field is deleted after the rule was saved, the run errors naming it. If Custom Fields is switched off entirely, the node skips with the reason on its trace instead, so a saved rule never starts erroring over a feature flag.

### Clear a Custom Field

`finding.clear_custom_field`

Removes one custom field's value from the Finding. The value it held is recorded on the Finding's provenance timeline, and a Finding holding no value counts as unchanged.

| Setting | Notes |
|---------|-------|
| **Field** | Which custom field to clear. |

## Assets

These nodes change Assets (Products). Like the Findings nodes, every change is attributed back to the rule, run and node that made it, and shows up on the Asset's provenance. They only join graphs whose trigger produces Assets.

These nodes save each Asset individually, so everything that normally follows an Asset edit still happens: organization membership follows a move, tag changes reconcile memberships, and Assets with tag inheritance enabled propagate added tags to their Findings.

### Set a Field

`asset.set_field`

Sets a field on the Asset. Assets already holding the value are left alone, and Assets the rule owner may not edit are counted on the node trace as skipped rather than touched.

| Setting | Default | Notes |
|---------|---------|-------|
| **Field** | none | One of: `description`, `business_criticality`, `platform`, `lifecycle`, `origin`, `user_records`, `revenue`, `external_audience`, `internet_accessible`. |
| **Value** | none | The control follows the field: a template for description (with `{{product.name}}` style placeholders), a picker for the choice fields, a number or a toggle for the rest. |

Two fields are deliberately not offered: `name` (it is unique, so one rendered value written across a sweep cannot work) and the SLA configuration (it drives an asynchronous recalculation with its own write lock, and belongs to a dedicated flow).

### Set Organization

`asset.set_organization`

Moves the Asset to a different Organization (Product Type). Its primary organization membership follows automatically, exactly as it does when the move is made on the Asset form.

| Setting | Default | Notes |
|---------|---------|-------|
| **Organization** | none | The destination. |

The permission gate mirrors the Asset form: the rule owner needs edit permission on each Asset, and the add-asset permission on the destination Organization. Without the latter the run fails up front, before anything moves.

### Add Tags

`asset.add_tags`

Adds tags to the Asset. Supports `{{product.name}}` style placeholders, so a sweep can tag by rendered value. On Assets with tag inheritance enabled, added tags propagate to their Findings.

| Setting | Default | Notes |
|---------|---------|-------|
| **Tags** | none | Comma separated tags. |

### Remove Tags

`asset.remove_tags`

Removes tags from the Asset. A tag the Asset does not carry is simply not removed, and counts the Asset as unchanged.

| Setting | Default | Notes |
|---------|---------|-------|
| **Tags** | none | Comma separated tags. |

### Set Parent

`asset.set_parent`

Places the Asset under a parent in the Asset hierarchy, or removes its parent. An edge the hierarchy refuses (a cycle, or the Asset being its own parent) is counted as failed on the node trace and skipped, rather than failing the run.

| Setting | Default | Notes |
|---------|---------|-------|
| **Action** | `Set Parent` | `Set Parent` or `Remove Parent`. |
| **Parent** | none | The Asset to place these under. Shown while the action is Set Parent. |

### Set a Custom Field

`asset.set_custom_field`

Writes one of this instance's [Custom Fields](/asset_modelling/pro__custom_fields/) on the Asset. The value control follows the field's data type exactly as the Findings node of the same name does (templates read `{{product.name}}` style paths), the same save-time and run-time validation applies, and a deleted field or a switched-off feature behaves the same.

| Setting | Notes |
|---------|-------|
| **Field** | Which custom field to write. One entry per Asset custom field defined on the instance. |
| **Value** | Typed to the field. |

Two behaviours of its own: Assets the rule owner may not edit are counted on the node trace as `skipped_unauthorized` rather than touched, and the write lands on the custom field value rather than the Asset row itself, so nothing that follows an Asset edit runs. A custom field edited by hand does not wake **On Asset Event** rules; a write made by a rule still cascades as an `updated` event.

### Clear a Custom Field

`asset.clear_custom_field`

Removes one custom field's value from the Asset, recording what it held on the Asset's provenance.

| Setting | Notes |
|---------|-------|
| **Field** | Which custom field to clear. |

### Naming a configuration or engine the rule owner cannot see

Both action nodes below only offer what their rule's owner is [permitted to see](/admin/user_management/user_permission_chart/#configuration-permission-chart) in their own picker — the same permission the SLA Configuration and Prioritization Engine settings pages themselves require. That is a picker-level convenience, not the only gate: a hand-written graph naming a configuration or engine the owner cannot see still resolves it when the rule runs, so it fails the run with an error naming it instead of silently doing nothing.

### Assign SLA Configuration

`asset.set_sla_configuration`

Assigns an SLA configuration to every Asset that reaches it. Findings under that Asset have their SLA expiration dates recalculated, exactly as [applying one by hand](/asset_modelling/pro_hierarchy/priority_sla/) on the Asset's own edit form does.

| Setting | Notes |
|---------|-------|
| **SLA Configuration** | Which SLA configuration to assign. Required. |

**An Asset already recalculating is skipped, not silently dropped.** If a person, or another rule, is already recalculating the same Asset's SLA dates when this node reaches it, writing here would not change anything and would be reverted, so the node counts that Asset as skipped instead of changed. The run's node summary reports the skip by name, alongside how many Assets were actually changed.

### Assign Risk Priority

`asset.set_risk_priority`

Assigns a Risk Priority — a [prioritization engine](/asset_modelling/pro_hierarchy/priority_sla/) — to every Asset that reaches it. Findings under that Asset are rescored asynchronously.

| Setting | Notes |
|---------|-------|
| **Risk Priority** | Which prioritization engine to assign. Required. |

Unlike the SLA action, this node does not skip an Asset that is mid-recalculation: nothing reverts its write, so the assignment lands normally either way.

### Assign to a Dedupe Pool

`asset.assign_dedupe_pool`

Makes the Asset deduplicate together with the rest of a [dedupe pool](/triage_findings/finding_deduplication/pro__dedupe_pools/), or removes it from one.

| Setting | Default | Notes |
|---------|---------|-------|
| **Action** | `Assign to Pool` | `Assign to Pool` or `Remove from Pool`. |
| **Pool** | none | Shown for `Assign to Pool`. The pool these Assets should deduplicate within. Required. |
| **Matching** | `Same tool` | Which kind of matching this membership governs: `Same tool` or `Cross tool`. Reimport matching is not offered, because a pool has no effect on it. |

## Egress

Egress nodes are the nodes that leave DefectDojo. Every one of them records a [Delivery](../deliveries/) before anything is sent, and every one of them honours the rule's **Simulate** or **Live** mode.

The notification nodes (Slack, Teams, email, SNS, webhook, in-app alert) work in Finding and Asset rules alike: in an Asset rule the default message line becomes the Asset's name and organization, digests count by business criticality instead of severity, and a webhook body carries an `assets` list plus an `entity` key (its `findings` list stays present and empty, so existing receivers never meet a missing key). The ticket nodes and the report node stay Finding-only: tickets and reports track Findings.

Several of them offer the same **One Message per Item** choice. Off, the node sends one message describing the whole batch, with a breakdown and a capped list of items. On, it sends one message per item.

A node sending one message per item stops after 1,000 sends in a single run by default, and records a visible skip saying how many items it did not send about. The ceiling counts items of either kind. See [Configuration](../configuration/#per-finding-send-ceiling).

### When a channel is unavailable

An egress node depends on something outside the rule: a Slack token, a Microsoft Teams webhook, a JIRA configuration, a licensed connector. When that is missing or switched off, the node cannot work, and Triage Engine says so at three different moments rather than failing quietly:

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

The summary, description and priority come from the Asset's JIRA configuration, not from this node. A ticket a rule creates is therefore identical to one created by push all issues.

### Create a Downstream Ticket

`ticket.downstream`

Creates or updates a ticket through a [Downstream Connector](/connectors/downstream/about/).

| Setting | Default | Notes |
|---------|---------|-------|
| **Issue Trackers** | `auto` | `auto` uses the issue trackers assigned to the engagement or Asset. `mapping` targets one specific mapping. |
| **Issue Tracker Mapping** | none | Shown for `mapping`. Which mapping to push to. |
| **Operation** | `create` | `create` a ticket, or `update` the one that exists. An update with no existing ticket creates it. |
| **Skip Findings That Already Have a Ticket** | on | Leaves Findings that already have a ticket in the target mapping alone. |

The rule replaces the assignment's automatic push settings: severity and active-only filters are not applied a second time here. A Finding whose ticket already exists is skipped however that ticket was created.

### Send a Slack Message

`notify.slack`

Posts to a Slack channel over a Messaging Connector. The connection carries the bot token; the instance-wide Slack settings under **System Settings** are not used and are not a fallback.

| Setting | Default | Notes |
|---------|---------|-------|
| **Connection** | none | A [Messaging Connector](/issue_tracking/pro_integration/messaging_connectors/) of this type. Required. |
| **Destination** | empty | Shown once a connection is chosen. The fields depend on the connection's vendor. |
| **One Message per Finding** | off | Off sends one message about the batch. |
| **Message** | `{{finding.severity}}: {{finding.title}} ({{product.name}})` | Rendered per Finding. |
| **Findings Listed in the Digest** | `10` | Shown for batch messages. How many Findings the message lists before it says how many more there were. |

### Send a Microsoft Teams Message

`notify.msteams`

Posts a card over a Messaging Connector. The connection carries the Power Automate workflow URL; the instance-wide Teams webhook under **System Settings** is not used and is not a fallback.

| Setting | Default | Notes |
|---------|---------|-------|
| **Connection** | none | A [Messaging Connector](/issue_tracking/pro_integration/messaging_connectors/) of this type. Required. |
| **Destination** | empty | Shown once a connection is chosen. The fields depend on the connection's vendor. |
| **One Message per Finding** | off | Off sends one card about the batch. |
| **Message** | `{{finding.severity}}: {{finding.title}} ({{product.name}})` | Rendered per Finding. |
| **Findings Listed in the Digest** | `10` | Shown for batch messages. |

### Send an Email

`notify.email`

Emails a fixed list of addresses over a Messaging Connector. The recipients are the connection's destination.

| Setting | Default | Notes |
|---------|---------|-------|
| **Connection** | none | A [Messaging Connector](/issue_tracking/pro_integration/messaging_connectors/) of this type. Required. |
| **Destination** | empty | Shown once a connection is chosen. The fields depend on the connection's vendor. |

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

### Publish to an SNS Topic

`notify.sns`

Publishes one message about the batch, or one per item, to an Amazon SNS topic, which fans it out to whatever is subscribed.

| Setting | Default | Notes |
|---------|---------|-------|
| **Connection** | none | A [Messaging Connector](/issue_tracking/pro_integration/messaging_connectors/) for Amazon SNS. Required. Unlike the chat channels, SNS has no instance-wide fallback: a connection is the only way to address a topic. |
| **Destination** | empty | Shown once a connection is chosen. The SNS topic to publish to, as its ARN. |
| **One Message per Finding** | off | Off publishes one message about the batch. |
| **Message** | `{{finding.severity}}: {{finding.title}} ({{product.name}})` | Rendered per Finding. |
| **Findings Listed in the Digest** | `10` | Shown for batch messages. How many Findings the message lists before it says how many more there were. |

### Raise an In-App Alert

`notify.alert`

Creates an in-app alert about the batch.

| Setting | Default | Notes |
|---------|---------|-------|
| **Title** | `Triage Engine: {{ctx.rule_name}}` | Rendered once for the whole batch. |
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
| **Findings Included** | `batch_findings` | `batch_findings` limits the report to the Findings that reached this node. `template_default` lets the template use its own filters. `trigger_tests` (Findings of the Triggering Imports) is for rules that start from **When a Scan Has Landed** or **When a Group of Scans Has Landed**: every Finding of the tests those imports wrote. |
| **Announce Over** | none | A [Messaging Connector](/issue_tracking/pro_integration/messaging_connectors/) to post the download link over once the report is generated. Leave empty to not announce. |
| **Announce To** | empty | Shown once a connection is chosen. Where that connection sends: a Slack channel ID, email addresses, and so on. |
| **Announcement** | `Report ready: {{ctx.report_url}}` | Shown when announcing. `{{ctx.report_url}}` is the download link; `{{ctx.import_summary}}` is the scan group's one-line account when the rule started from a group of scans, and empty otherwise. |

`batch_findings` is what a rule can do that a scheduled report cannot: report on exactly the Findings that just matched.

The announcement is recorded as its own delivery, separate from the report generation, so you can see the report succeed and the announcement fail independently.
