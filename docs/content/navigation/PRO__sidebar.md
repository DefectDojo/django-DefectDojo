---
title: "The Sidebar Menu"
description: "How the DefectDojo Pro sidebar is organized, the All Settings directory page, and how to switch between the current and previous layouts"
weight: 6
audience: pro
aliases:
  - /navigation/pro__settings_menu/
---

The DefectDojo Pro sidebar groups every page in the product into six sections, ordered by how the product is used rather than by how its data is structured. The views you open to find work come first; the record catalogs you drill into sit below them. Which layout you see depends on when your instance was created:

- **New installations** open on the reorganized layout described below.
- **Existing installations** keep the previous layout until an administrator turns on **Menu 2.0** (see [Switching layouts](#switching-layouts)).

Either way, **every page keeps the same URL**. Bookmarks, saved links and anything in your own runbooks continue to work regardless of which layout is active.

## The six sections

| Section | What it holds |
| --- | --- |
| **Overview** | Home, My Work, Insights, Reporting, Calendar |
| **Sensei + AI** | AppSec, CSPM, Threat Modeling, MCP, AI Model Settings |
| **PSIRT** | Triage, Sources & Inventory, Configuration |
| **Manage** | Attack Surface, Rules Engine, Root Causes, Vulnerability Explorer, Organizations, Assets, Engagements, Tests, Findings, Surveys |
| **Connect** | Upstream Connectors, Downstream Connectors, Jira, Authorization, Diagnostics, Import |
| **Settings** | All Settings, plus the seven groups described under [The Settings section](#the-settings-section) |

You only ever see the entries your account has permission to open, and a group disappears entirely when none of its pages are available to you.

Three conventions run through the whole menu:

- **There are no separate "New" entries.** Each list page has a **New** button that opens the create form, so the menu carries one entry per catalog instead of two. If your account can create a record but not list them, the menu entry takes you straight to the create form.
- **Nothing nests more than one level below a section.** Reaching a page is at most section, group, page.
- **A feature occupies one entry, not one per screen.** Attack Surface and the Rules Engine each hold their pages under a single entry instead of spreading them across the menu.

## Sensei + AI

The AI capabilities sit together in their own section rather than being spread through the dashboards.

**AppSec** is the Sensei code security capability, and was previously listed simply as **Sensei**. The page and its URL are unchanged. The name changed because Sensei now covers more than one capability, so the entries beside it name what each one does.

**CSPM** carries a gold `SOON` badge. Cloud security posture management is not available yet, so the entry does not open a page. Selecting it explains that the capability is on the way. Nothing needs enabling, and no license unlocks it early. The entry starts working when the capability ships.

**Threat Modeling**, **MCP** and **AI Model Settings** are unchanged apart from where they live. AI Model Settings appears only on on-premise instances, because DefectDojo manages the model credentials on Cloud.

## PSIRT

Product Security Incident Response has its own section rather than an entry inside Manage. It is a workflow of its own, with its own licence and its own settings, and its nine pages sit in three groups:

| Group | Pages |
| --- | --- |
| **Triage** | Feed Findings, Cases, Advisories |
| **Sources & Inventory** | Advisory Feeds, Components, Import SBOM, Matching Rules |
| **Configuration** | SLA Policies, PSIRT Settings |

Triage leads because that is where the work happens: an advisory arrives, you decide whether it affects you, related matches become a case, and what you publish about your own products comes out the far end. Sources & Inventory is what the queue runs on, and the last two pages are configuration rather than workflow.

Each group carries a `BETA` badge, or a `LOCKED` one if your licence does not include the PSIRT Advisory Engine. See [Menu Badges](/navigation/pro__menu_badges/).

## Manage

Manage leads with the views people open to find work, and keeps the record catalogs below them. **Attack Surface**, the **Rules Engine**, **Root Causes** and the **Vulnerability Explorer** come first; Organizations, Assets, Engagements, Tests and Findings follow. That ordering is deliberate: the Organization to Finding chain is how DefectDojo stores your data, but it is not how most people navigate to the work in front of them.

Three entries in the previous layout answered the same question, which is where a finding lives. **Attack Surface** now holds them in one place: Components, plus either the endpoint pages or the location pages depending on whether your instance uses Locations.

**Findings** absorbs the pages that describe a finding's state rather than a separate kind of record, so Risk Acceptances is listed there. The Vulnerability Explorer stays at the top level, because it is somewhere you start rather than a view of a catalog.

**Rules Engine** is one entry covering both engines. When both are turned on, the classic engine's pages appear beneath the Rules Engine 2.0 pages and carry a `LEGACY` badge linking to the conversion guide. When only one engine is on, only its pages are listed, and no badge appears.

## Connect

Connect answers what is connected to this instance and whether it is working. **Import** now sits at the bottom of it, holding Add Findings, Smart Upload, Unassigned Findings, the Universal Importer and the Universal Parser. These were previously a separate Import section, which split scanning tools across two places depending on whether findings arrived by connector or by upload. It sits last because the connectors are the standing, automatic path, and a manual upload through the browser is the exception.

**Smart Upload** and **Unassigned Findings** can be removed from this group with the **Smart Upload** feature flag, which is on by default. Turning it off hides both entries and changes nothing else; findings already imported through Smart Upload are unaffected.

## The Settings section

Settings is divided into seven groups, named for what you are trying to do rather than for the part of the system involved.

| Group | What it holds |
| --- | --- |
| **System** | System Settings, Appearance, Announcement Banner, Login Banner, E-mail, Feature Flags |
| **Users & Permissions** | Users, Groups, Roles |
| **Finding Workflow** | The three Deduplication pages, Finding Enrichment, Service Level Agreements, Prioritization Engines, Mitigation Policies |
| **Configuration** | Environments, Regulations, Note Types, Test Types, CI/CD Infrastructure, Tool Types, Tool Configurations |
| **Notifications** | Notification Events, Notification Webhooks |
| **Operations** | Audit Logs, Usage Logs, Schedules, Celery Status, and on DefectDojo Cloud, Message Portal, Firewall Rules, Maintenance Windows |
| **License & Support** | License Manager, Version Manager, Contact Support |

### All Settings

The first entry in the section, **All Settings**, opens a directory of every settings page your account can reach, arranged in the same groups as the menu and searchable by name or by what the page does. Searching `deduplication` finds the three deduplication pages *and* System Settings, because System Settings holds deduplication options too.

The last category, **Elsewhere in the app**, lists pages that configure DefectDojo but live in other sidebar sections: the authorization providers, Login and MFA settings, Jira instances, the Upstream and Downstream connectors, and the Universal Parser. Each tile is chipped with the section it belongs to.

## What moved

If you are used to the previous layout:

| Previously | Now |
| --- | --- |
| Dashboards | Overview |
| Dashboards → Sensei | Sensei + AI → AppSec |
| Dashboards → Threat Modeling / MCP / AI Model Settings | Sensei + AI |
| Dashboards → PSIRT Feeds, and the eight other PSIRT entries | The PSIRT section |
| Dashboards → Metrics | Overview → Insights |
| Dashboards → Reporting → Report Templates → All / New | Overview → Reporting → Report Templates |
| Import → *(whole section)* | Connect → Import *(last entry)* |
| Import → Smart Upload → Add Findings | Connect → Import → Smart Upload |
| Connect → Upstream / Downstream | Connect → Upstream Connectors / Downstream Connectors |
| Manage → Endpoints / Locations / Components | Manage → Attack Surface |
| Manage → Risk Acceptances | Manage → Findings → Risk Acceptances |
| Manage → Root Causes / Vulnerability Explorer | Manage → *(unchanged, now near the top)* |
| Manage → Rules Engine and Rules Engine 2.0 | Manage → Rules Engine |
| Manage → *(any)* → New *(record)* | The **New** button on the matching list page |
| Settings → *(top level)* → Feature Flags | Settings → System → Feature Flags |
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

The group that was named after your license package, **Pro Settings** on a Pro instance and **Enterprise Settings** on an Enterprise one, no longer exists. Its pages are distributed across System, Finding Workflow, Notifications and Operations.

## Turning entries off

Three sidebar entries can be removed from [Feature Flags](/admin/feature_flags/pro__feature_flags/) by an administrator. All three are on by default, and turning one off removes the entry without changing any data behind it.

| Flag | Removes |
| --- | --- |
| **Calendar** | Calendar, from Overview |
| **Smart Upload** | Smart Upload and Unassigned Findings, from Connect > Import |
| **PSIRT** | the whole PSIRT section |

The Calendar toggle used to be **Enable Calendar** in System Settings. It moved so that the switches which add or remove a menu entry sit together in one place. Your existing choice is carried across on upgrade: an instance that had the calendar switched off keeps it off, and the System Settings checkbox disappears once the reorganized menu is on. Instances still on the previous layout keep using that checkbox.

## Switching layouts

**Menu 2.0** on the [Feature Flags](/admin/feature_flags/pro__feature_flags/) page controls which layout is active. Turning it on or off reshapes the sidebar immediately; no restart is needed and nothing else about your instance changes.

New installations start with it on. Existing installations start with it off, so an upgrade never rearranges the menu under a team mid-flight. Turn it on when your administrators are ready.

While it is off, the **All Settings** page is unavailable and its URL returns Not Found.

## Related

* [Menu Badges](/navigation/pro__menu_badges/): what the `NEW`, `BETA`, `SOON`, `LEGACY` and `DEPRECATED` tags mean
* [Feature Flags](/admin/feature_flags/pro__feature_flags/): turning optional features on and off
