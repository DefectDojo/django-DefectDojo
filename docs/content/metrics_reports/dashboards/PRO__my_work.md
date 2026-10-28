---
title: "My Work"
description: "A per-user queue of the Findings, reviews, Risk Acceptances and remediation actions waiting on you, ordered by deadline"
audience: pro
weight: 4
---

**My Work** answers one question: what is waiting on me, and what is due first? It is a per-user view. The same page shows each person their own work.

Open it from **Overview > My Work** in the left sidebar.

## What is on the page

My Work gathers everything that needs you into one list and sorts it by deadline:

| Reason | What it means |
| --- | --- |
| **Assigned to Me** | An active Finding assigned to you personally. |
| **Review Requested** | A Finding where you were asked to review and nobody has claimed the review yet. |
| **Review Claimed** | A Finding whose review you claimed. |
| **Acceptance Expiring** | A Risk Acceptance you own or are assigned to that expires within the next 30 days, or expired in the last 30 days. |
| **Remediation Action** | An open remediation action assigned to you. Shown when Remediation Center is enabled. |

Each item shows its reason as a tag. A Finding that is both assigned to you and waiting on your review appears once, with its review reason.

Everything is scoped by your permissions. My Work never shows you something you could not otherwise see.

### Deadline sections

Items are grouped by how soon they are due. For a Finding, that is its SLA. For a Risk Acceptance, its expiration date. For a remediation action, its due date.

| Section | What it holds |
| --- | --- |
| **Overdue** | Past due, or due today. |
| **Due in 7 Days** | Due in the next seven days. |
| **Later** | Due more than seven days from now. |
| **No Due Date** | Findings with no SLA date. Collapsed by default. |
| **Waiting on Others** | Reviews you requested that nobody has cleared yet. Collapsed by default. |

Inside a section, the most urgent item comes first, then the most severe. **Show More** at the foot of a section loads the next page.

### Counters

The row of counters at the top shows how many items are **Overdue**, how many are **Due This Week**, how many **Reviews Waiting** on you, and how many reviews you are **Waiting on Others** for. Select **Reviews Waiting** or **Waiting on Others** to show only reviews.

### Filtering by kind

The selector above the sections narrows the page to one kind of work: **All**, **Findings**, **Reviews**, **Acceptances** or, when Remediation Center is enabled, **Remediation**. Each option shows how many items it holds.

## List, Grid and Board views

The buttons at the top right switch between three layouts. My Work remembers your choice.

* **List View** shows each section as a table: severity, title, asset, reason, due date and next step.
* **Grid View** shows each item as a card.
* **Board View** shows the deadline sections side by side as columns of cards, each column scrolling on its own. The board is read-only: cards do not move between columns, because a column is set by the item's deadline. Board View is not offered on narrow screens.

## Next steps

Each item carries a **Next Step** button for the most likely action:

| Item | Next step |
| --- | --- |
| Assigned Finding | **Close Finding** |
| Review you can claim | **Take Review** |
| Review you hold | **Clear Review** |
| Risk Acceptance | **Edit Risk Acceptance** |
| Remediation action | **Change Status** |

Each button opens the same form you would reach from the Finding, Risk Acceptance or remediation action itself. Nothing changes until you submit the form. A step appears only when you have permission to take it. The item's menu still offers every other action.

## Working through the queue

**Start Triage** opens [Keyboard Triage](/triage_findings/findings_workflows/pro__keyboard_triage/) on the Findings in My Work, most urgent first. **Back to My Work** returns you here.

## My Team's Queue

Below the deadline sections, **My Team's Queue** lists active Findings owned by a group you belong to. Owners is group-level, so this is your team's work rather than yours specifically. It is a full Findings list, so the usual filtering, sorting and column controls work.

## On a dashboard

The same content is available as a **My Work** widget for [custom dashboards](../custom-dashboards/), so you can put your queue alongside other metrics. Add the widget and choose which queues to show and how many rows each should carry.

There is also a ready-made **My Work** dashboard template under the **Personal** category, which pairs the widget with SLA burndown and recent activity.

## Why a queue rather than notifications

Notifications can be missed, filtered, or arrive while you are not looking. My Work is the durable version: anything waiting on you is here whether or not a notification reached you.

That is why some notifications can be narrowed without losing work. A reviewer who has [scoped their review-request notifications](/admin/notifications/about_notifications/#narrowing-review-request-notifications-pro) to particular assets still sees every request in My Work. The notification is suppressed, the work is not.
