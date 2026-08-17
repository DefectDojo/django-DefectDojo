---
title: "The Settings Menu"
description: "How the Settings section of the DefectDojo Pro sidebar is organized, the All Settings directory page, and how to switch between the current and previous layouts"
weight: 6
audience: pro
---

The Settings section of the sidebar groups every administrative page in DefectDojo Pro. Which layout you see depends on when your instance was created:

- **New installations** open on the reorganized layout described below.
- **Existing installations** keep the previous layout until an administrator turns on **Menu 2.0** (see [Switching layouts](#switching-layouts)).

Either way, **every settings page keeps the same URL**. Bookmarks, saved links and anything in your own runbooks continue to work regardless of which layout is active.

## The reorganized layout

Settings is divided into eight groups, named for what you are trying to do rather than for the part of the system involved.

| Group | What it holds |
| --- | --- |
| **System** | System Settings, Appearance, Announcement Banner, Login Banner, E-mail |
| **UI Defaults** | Form Configuration, Layout Defaults |
| **Users & Permissions** | Users, Groups, Roles |
| **Finding Workflow** | The three Deduplication pages, Finding Enrichment, Service Level Agreements, Prioritization Engines, Mitigation Policies |
| **Configuration** | Environments, Regulations, Note Types, Test Types, CI/CD Infrastructure, Tool Types, Tool Configurations |
| **Notifications** | Notification Events, Notification Webhooks |
| **Operations** | Audit Logs, Usage Logs, Schedules, Celery Status, and — on DefectDojo Cloud — Message Portal, Firewall Rules, Maintenance Windows |
| **License & Support** | License Manager, Version Manager, Contact Support |

You only ever see the entries your account has permission to open, and a group disappears entirely when none of its pages are available to you.

**Feature Flags sits above the groups**, directly under All Settings, rather than inside any of them. It is the page administrators open most often, and it reads alongside All Settings: one lists what exists, the other controls what is switched on. It is still filed under System in the All Settings directory.

Two conventions are worth knowing:

- **There are no separate "New" entries.** Each list page has a **New** button that opens the create form, so the menu carries one entry per catalog instead of two. If your account can create a record but not list them, the menu entry takes you straight to the create form.
- **Nothing nests more than one level below a group.** Reaching a page is at most Settings → group → page.

## All Settings

The first entry in the section, **All Settings**, opens a directory of every settings page your account can reach, arranged in the same groups as the menu and searchable by name or by what the page does. Searching `deduplication` finds the three deduplication pages *and* System Settings, because System Settings holds deduplication options too.

The last category, **Elsewhere in the app**, lists pages that configure DefectDojo but live in other sidebar sections — the authorization providers, Login and MFA settings, Jira instances, the Upstream and Downstream connectors, and the Universal Parser. Each tile is chipped with the section it belongs to.

## UI Defaults

The **UI Defaults** group collects the settings that control how much of the interface each person can tailor:

- **Form Configuration**: choose which fields the create and edit forms show and require, and whether the Optional Fields panel starts expanded.
- **Layout Defaults**: the **Restrict Layout Customization** switch, plus the global defaults designated for dashboards, page layouts, and table views. With the switch on, only superusers can create or change dashboards, page layouts, and table views; everyone else is shown the designated defaults, or the built-in defaults when none are chosen. Personal layouts saved earlier are kept and reappear if the switch is turned back off. You choose each default from a dropdown of the layouts an administrator has shared, or designate one in context (a shared dashboard's Manage dialog, a view page's layout menu, or a table's Views menu).

## What moved

If you are used to the previous layout:

| Previously | Now |
| --- | --- |
| Settings → *(top level)* → Feature Flags | Unchanged — still at the top level, below All Settings |
| Settings → Pro Settings → System Settings | Settings → System → System Settings |
| Settings → Pro Settings → Appearance | Settings → System → Appearance |
| Settings → Pro Settings → Banner Settings → Announcement Banner Settings | Settings → System → Announcement Banner |
| Settings → Pro Settings → Banner Settings → Login Banner Settings | Settings → System → Login Banner |
| Settings → Pro Settings → E-mail Settings | Settings → System → E-mail |
| Settings → Users → All Users / New User | Settings → Users & Permissions → Users |
| Settings → Users → All Groups / New Group | Settings → Users & Permissions → Groups |
| Settings → Users → Roles | Settings → Users & Permissions → Roles |
| Settings → Pro Settings → Deduplication Settings → *(three pages)* | Settings → Finding Workflow → Same Tool / Cross Tool / Reimport Deduplication |
| Settings → Pro Settings → Finding Enrichment Settings | Settings → Finding Workflow → Finding Enrichment |
| Settings → Configuration → Service Level Agreements | Settings → Finding Workflow → Service Level Agreements |
| Settings → Configuration → Prioritization Engines | Settings → Finding Workflow → Prioritization Engines |
| Settings → Configuration → Mitigation Policies | Settings → Finding Workflow → Mitigation Policies |
| Settings → Configuration → *(reference-data catalogs)* | Settings → Configuration → *(unchanged)* |
| Settings → Pro Settings → Notification Settings | Settings → Notifications |
| Settings → Configuration → Audit Logs | Settings → Operations → Audit Logs |
| Settings → Configuration → Usage log | Settings → Operations → Usage Logs |
| Settings → Configuration → All Schedules | Settings → Operations → Schedules |
| Settings → Pro Settings → Celery Status | Settings → Operations → Celery Status |
| Settings → Cloud Manager → *(cloud pages)* | Settings → Operations |
| Settings → License Manager / Version Manager / Contact Support | Settings → License & Support |

The group that was named after your license package — **Pro Settings** on a Pro instance, **Enterprise Settings** on an Enterprise one — no longer exists. Its pages are distributed across System, Finding Workflow, Notifications and Operations.

## Switching layouts

**Menu 2.0** on the [Feature Flags](/admin/feature_flags/pro__feature_flags/) page controls which layout is active. Turning it on or off reshapes the sidebar immediately; no restart is needed and nothing else about your instance changes.

New installations start with it on. Existing installations start with it off, so an upgrade never rearranges the menu under a team mid-flight — turn it on when your administrators are ready.

While it is off, the **All Settings** page is unavailable and its URL returns Not Found.
