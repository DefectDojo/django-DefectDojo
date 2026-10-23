---
title: "Keyboard Triage"
description: "Walk a Findings list one Finding at a time from the keyboard, with a note for each decision, in DefectDojo Pro"
audience: pro
weight: 3
---

**Triage** walks a Findings list one Finding at a time. The list's filters and sort order become the queue, so Triage on the Active Findings page filtered to High severity walks exactly those Findings, in that order. No key changes a Finding by itself: **n** opens the Add Note form for the Finding, and the note is saved only when the form is submitted.

Triage is a beta feature behind the **Keyboard Triage** feature flag, which is on by default.

## Opening Triage

From any Findings list (All, Active, Verified, Mitigated, Duplicate or Risk Accepted Findings), click **Triage** in the toolbar, or press **t**. The Triage button is shown to users who can edit Findings.

**Back to Findings**, or **Esc**, returns to the list with its filters and sort as they were.

## The Triage page

- **The counter** beside the title shows which Finding is open and how many the list holds, for example **14 of 212**.
- **The queue** on the left lists the Findings in the list's order, with their severity and Asset. The current Finding is outlined, and a check mark shows each Finding given a note or skipped in this session. Click a row to jump to that Finding.
- **The Finding** on the right shows its title (a link to the Finding page), severity and status, the Organization, Asset, Engagement and Test it belongs to, its assignees, and its description and mitigation.
- **The key legend** under the Finding lists the keys. The note key is greyed out on a Finding the user cannot add a note to.

## Keys

| Key | Action |
| --- | --- |
| **j** / **k** | Next / previous Finding |
| **]** | Skip the Finding (counted as seen, nothing is changed) |
| **[** | Back one Finding |
| **n** | Open the Add Note form for the Finding (nothing is saved until the form is submitted) |
| **Enter** | Open the Finding page (**Cmd+Enter** / **Ctrl+Enter** opens it in a new tab) |
| **Esc** | Leave Triage and return to the list |
| **?** | Show every keyboard shortcut |

Keys never fire while typing in a field or while a dialog is open, so typing a note never moves the queue.

## Adding a note

**n** opens the same **Add Note** form as the Finding's own menu, with the note entry, note type and the **Private** option. Submitting the form saves the note, marks the Finding with a check mark in the queue and keeps Triage on that Finding; **j** or **]** moves on. Closing the form without submitting saves nothing. Adding a note also records the Finding as reviewed, by the user and at that time.

Any other change to a Finding (its severity, its status, closing it) is made on the Finding page: press **Enter** to open it, or **Cmd+Enter** / **Ctrl+Enter** to open it in a new tab and stay in Triage.

## Permissions

Triage reads the same Findings the list shows. On a Finding the user cannot add a note to, Triage says so, greys out **n** and ignores it; moving through the queue and opening the Finding still work. A note the server refuses shows the server's reason, and the form stays open with what was typed.

## When the queue is done

Moving past the last Finding shows **Queue Complete**, with how many Findings were reviewed (given a note or skipped). **Start Again** reloads the queue from the list's current results, and **Back to Findings** returns to the list.
