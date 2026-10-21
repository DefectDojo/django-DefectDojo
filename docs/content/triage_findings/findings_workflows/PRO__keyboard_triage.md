---
title: "Keyboard Triage"
description: "Walk a Findings list one Finding at a time and decide each with a single key in DefectDojo Pro"
audience: pro
weight: 3
---

**Triage** walks a Findings list one Finding at a time. The list's filters and sort order become the queue, so Triage on the Active Findings page filtered to High severity walks exactly those Findings, in that order. Each decision is a single key, and it is saved the moment the key is pressed.

Triage is a beta feature behind the **Keyboard Triage** feature flag, which is on by default.

## Opening Triage

From any Findings list (All, Active, Verified, Mitigated, Duplicate or Risk Accepted Findings), click **Triage** in the toolbar, or press **t**. The Triage button is shown to users who can edit Findings.

**Back to Findings**, or **Esc**, returns to the list with its filters and sort as they were.

## The Triage page

- **The counter** beside the title shows which Finding is open and how many the list holds, for example **14 of 212**.
- **The queue** on the left lists the Findings in the list's order, with their severity and Asset. The Finding being decided is outlined, and a check mark shows each Finding decided or skipped in this session. Click a row to jump to that Finding.
- **The Finding** on the right shows its title (a link to the Finding page), severity and status, the Organization, Asset, Engagement and Test it belongs to, its assignees, and its description and mitigation.
- **The key legend** under the Finding lists the keys. Keys the current Finding does not allow are greyed out.

## Keys

| Key | Action |
| --- | --- |
| **j** / **k** | Next / previous Finding |
| **]** | Skip the Finding (counted as seen, nothing is changed) |
| **[** | Back one Finding |
| **1** to **5** | Set the severity to Critical, High, Medium, Low or Info, and stay on the Finding |
| **v** | Turn Verified on or off, then move to the next Finding |
| **f** | Turn False Positive on or off, then move to the next Finding |
| **o** | Turn Out of Scope on or off, then move to the next Finding |
| **u** | Turn Under Review on or off, then move to the next Finding |
| **Enter** | Open the Finding page (**Cmd+Enter** / **Ctrl+Enter** opens it in a new tab) |
| **Esc** | Leave Triage and return to the list |
| **?** | Show every keyboard shortcut |

Keys never fire while typing in a field or while a dialog is open.

### How the status keys change a Finding

The status keys follow the same rules as [bulk editing](/triage_findings/findings_workflows/pro__bulk_edit_findings/), so a Finding never ends up in a combination the bulk edit form would not allow:

- **Verified** clears False Positive, Out of Scope and Under Review.
- **False Positive** and **Out of Scope** close the Finding: it becomes inactive and mitigated, and is no longer verified or under review. Turning either one back off reopens the Finding.
- **Under Review** keeps the Finding active and clears the other flags.

## Permissions

Triage reads the same Findings the list shows. On a Finding the user cannot edit, Triage says so, greys out the decision keys and ignores them; moving through the queue still works. A change the server refuses (for example, a permission removed while Triage is open) shows the server's reason once, and the Finding stays where it was.

## When the queue is done

Moving past the last Finding shows **Queue Complete**, with how many Findings were reviewed and how many decisions were made. **Start Again** reloads the queue from the list's current results, and **Back to Findings** returns to the list.
