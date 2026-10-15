---
title: "Remediation Center"
description: "Group open Findings by the change that resolves them, one remediation action per change per location, with a due date, owners, workflow status and campaign rollups"
weight: 1
audience: pro
---

One outdated library on one Asset can produce dozens of Findings, and every one of them is
closed by the same upgrade. The **Remediation Center** turns open Findings into the work that
fixes them. It groups Findings by the change that resolves them into **remediation actions**,
one per change per location, and gives each action a due date, an owner, and a workflow status.

The Remediation Center adds a layer on top of your Findings. It does not replace them. Findings
stay the evidence underneath each action, and each Finding keeps its own status, SLA, and history.
You keep triaging and closing Findings as before. The action tracks the result.

## Enabling the Remediation Center

The Remediation Center is a **beta** feature behind the `remediation_center` feature flag. A
superuser can turn it on from **Settings > Feature Flags**. See
[Feature Flags](/admin/feature_flags/pro__feature_flags/).

While the flag is off, the Remediation Center pages, its settings page and its API endpoints are
unavailable.

Actions are built from open Findings after each import, and once a night for every Asset. If the
Action Queue is empty right after you turn the flag on, use **Build Actions Now** on the Overview
page to group existing open Findings immediately.

## Where it appears

When the flag is on, a **Remediation Center** entry (marked **BETA**) appears in the **MANAGE**
section of the sidebar, with three pages:

- **Overview**: open Findings grouped into the changes that fix them, and how late that work runs.
- **Action Queue**: the list of remediation actions, filterable by **All Work**, **Assigned to
  Me** and **My Teams**.
- **Campaigns**: the same change rolled up across every Asset that needs it.

Superusers also get **Settings > Configuration > Remediation Center**, where the SLA windows and
due-date alerts are set (see [Settings](#settings)).

## What a remediation action is

A remediation action is one change on one place that resolves a set of Findings. "Upgrade
`example-lib` from 1.2.0 to 1.4.1 in `package-lock.json`" is one action. The same upgrade on a
different Asset is a different action.

Each action records:

- **What to change.** An action type, such as Upgrade, Patch, Configuration change, Code change,
  Rebuild, Removal, Certificate replacement, Permission change, Decommission, or Other. For
  component upgrades, the action also shows the current and target versions.
- **Where to change it.** The Asset, plus a location within it: a host, a code location, a
  manifest, a container image, a web site, a cloud resource, or the Asset as a whole. An action
  never spans more than one Asset.
- **What it resolves.** The Findings grouped under it, with counts of open Findings, CVEs and
  KEV entries, and the highest severity and risk among the open Findings.

The **target version** is the highest fixed version the Findings name, so one upgrade covers
every lower fix. Each action also carries a **Grouping Rationale** that shows why its Findings
were grouped together, marked as an **Exact Match**, a **Heuristic Match**, or **Grouped by
Hand**.

A Finding belongs to at most one action. Closed Findings stay attached to their action, so an
action keeps a record of everything it resolved.

### Adjusting the grouping

The grouping is a suggestion you can change. From an action you can:

- **Split Into a New Action**: move some of its Findings into a new action.
- **Move to Another Action**: move Findings into another open action on the same Asset.
- **Merge Other Actions Into This One**.
- **Edit Action**: change the title, action type, target version, or remediation steps.
- **Suppress**: hide the action from work queues, with a reason. **Restore to the Queue**
  brings it back with its owner, due date and history as they were.
- **Hand Back to Automatic Grouping**: return Findings you placed by hand to wherever automatic
  grouping puts them.

Findings you place by hand stay where you put them when the Asset is regrouped. Fields you edit
are left alone by later regrouping until you reset them.

## Due dates and SLA state

An action's due date is the **earliest SLA expiration date among its open Findings**. The action
records which Finding sets that deadline. The due date moves on its own when Findings are added,
closed, reopened, or risk accepted.

The action does not change the Findings' SLAs. Each Finding keeps the SLA it was given by its
Asset's SLA configuration.

Each action shows an SLA state computed from its due date:

| SLA state | Meaning |
|---|---|
| **Overdue** | The due date has passed. |
| **At Risk** | Due within the **At Risk Within (Days)** window (3 days by default). |
| **Due Soon** | Due within the **Due Soon Within (Days)** window (14 days by default). |
| **On Track** | Due later than both windows. |
| **No Due Date** | None of the open Findings has an SLA date. |

## Owners

Each action has two kinds of owner:

- **Assignee**: the person carrying out the change. Assign from the action, or select several
  actions in the Action Queue and assign them at once. The assignee must be able to view the
  action's Asset.
- **Team**: the owning team. By default this is the group that owns the most open Findings in the
  action (the Finding's owners group). You can change it from the action's **Ownership** panel.

## Workflow status

An action moves through these statuses:

| Status | Notes |
|---|---|
| **New** | The starting status for an action. |
| **Planned** | |
| **In Progress** | |
| **Blocked** | Requires a reason saying what is blocking the action. |
| **Change Scheduled** | Requires the date the change is scheduled for. The date cannot be in the past. |
| **Awaiting Validation** | Use this once the change is made and you are waiting for a rescan or review to confirm it. |
| **Exception Requested** | |
| **Complete** | Set automatically. You cannot choose it. |

An action becomes **Complete** on its own when every Finding it resolves is closed. If at least
one of those Findings was fixed (mitigated), the timeline records the action as validated.
Closing every Finding as risk accepted, false positive, out of scope or duplicate also completes
the action, without recording a fix. If a closed Finding reopens, or a new open Finding joins a
complete action, the action reopens.

Each action has an **Activity** timeline showing comments and every change: who made it and when.

## Tickets

From an action, **Create Ticket** gives you a ready-made description to copy into your tracker.
You then link the ticket back to the action. The pattern is one ticket per action.

## Campaigns

A **campaign** groups every action that makes the same change, across all Assets. For example,
upgrading `example-lib` to 1.4.1 on twelve Assets is twelve actions and one campaign. Campaigns
are what a team lead plans from.

Each campaign shows a rollup of its actions:

- the number of actions, open actions and completed actions;
- the number of Assets involved;
- open Findings across all its actions;
- the earliest due date among its open actions, and how many of them are overdue;
- the highest risk among its actions;
- progress, as the share of its actions that are complete.

Campaigns are built and updated automatically. You do not create them by hand.

## Settings

**Settings > Configuration > Remediation Center** holds the instance-wide settings. Anyone with
access can read them. Only superusers can change them.

- **SLA Windows**: **At Risk Within (Days)** (default 3) and **Due Soon Within (Days)** (default
  14) set the SLA state thresholds above.
- **Due-Date Alerts**: **Send Due-Date Alerts** turns alerts on or off (on by default).
  **Alert Days Before Due Date** sets when they go out (30, 14, 7, 3 and 1 days before the due
  date by default).

Alerts go to the action's assignee, or to the owning team's members while nobody is assigned.
The Asset's managers and contacts receive an escalation when an action is overdue, blocked close
to its deadline, or coming due with no assignee and no owning team. Each person gets one message
per day listing their actions, and only people who can view the action's Asset are notified.

## Permissions

The Remediation Center follows the same Asset permissions as the rest of DefectDojo:

- You see actions only for Assets you can view, and only the Findings you are allowed to see.
- Changing status, assigning, setting the team, commenting and linking tickets requires
  permission to edit Findings on the Asset.
- Changing the grouping (edit, split, move, merge, suppress, regroup) requires permission to edit
  the Asset.

## API

The Remediation Center is available on the public API for automation such as ticket bridges,
reporting, and bulk assignment. Requests use a normal API token. The endpoints return an error
while the feature flag is off.

- `/api/v2/remediation_actions/`: list and retrieve actions, plus actions to change status,
  assign, set the team, comment, link a ticket, edit, split, move, merge, suppress, and export
  (CSV, Excel, or JSON).
- `/api/v2/remediation_campaigns/`: list and retrieve campaigns with their rollups.
- `/api/v2/remediation_center_settings/`: read the settings. Superusers can update them.

See the API documentation on your instance for the full list of endpoints and fields.
