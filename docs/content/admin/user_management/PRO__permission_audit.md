---
title: "Permission Audit and Effective Access"
description: "See what every user and group can reach, why, and export it for an access review"
audience: pro
weight: 3
---

Access in DefectDojo adds up from several places: a Global Role, Roles on Organizations and Assets, Roles held through Groups, Organization Types, and Configuration Permissions. The **Permission Audit** mode on the Users list and the **Access** tab on each user's page bring those together, so an administrator can answer "who can see this, and why" without opening every Asset.

These pages are part of **Access Administration**, a beta feature that is on by default. A Superuser can turn it off under **Settings > Feature Flags**.

## Who can use it

Permission Audit and the Access tab of another user are shown to Superusers, Global Owners, and users who hold the permission to view users. Every user can open the Access tab on their own page.

Counts and lists only include what the person reading them can see. An Asset or Organization the reader cannot see is never named. On the Access tab it is counted under its table ("And 4 more you cannot see.").

## Permission Audit on the Users list

1. Navigate to **Settings > Users & Permissions > Users**.
2. Click **Permission Audit** in the table toolbar. Click it again to return to the usual list.

In Permission Audit mode the list adds these columns:

* **Flags**: Elevated, No Access and Inactive (see below).
* **Global Roles**: the user's own Global Role and those of their Groups.
* **Configuration Permissions**: how many Configuration Permissions the user holds.
* **Organizations** and **Assets**: how many the user holds a Role on, directly, through a Group, through an Organization Type, or (for Assets) through their Organization. A user with a Global Role, and a Superuser, shows **All**.
* **Groups**: the Groups the user belongs to.

Each column can be filtered, and the counts can be sorted. Clicking a username opens that user's **Access** tab.

### The three flags

| Flag | Shown when |
| --- | --- |
| **Elevated** | The user is a Superuser, holds a Global Role with Owner-level permissions, holds any Configuration Permission, or belongs to a Group that holds a Global Role. |
| **No Access** | The user has no Asset or Organization Role, no Global Role and no Group. |
| **Inactive** | The user has not signed in for 90 days, or never has. |

A useful review starts with **Elevated** and **Inactive** together: accounts that hold broad access they no longer use.

### Exporting

With Permission Audit on, **Export** offers the audit columns alongside the usual user fields. The export contains the same users as the list, with the same filters applied.

## The Access tab on a user's page

Open a user and select the **Access** tab. It shows:

* An **Access Summary**: the user's flags, Global Roles and Configuration Permissions, each with where it comes from.
* **Organizations**, **Assets** and **Groups** tables, each listing the Role and a **Via** column: **Direct**, **Group** with the Group's name, **Facet** with the Organization Type, or (for Assets) the **Organization** the Asset is reached through.

Each table can be searched by name and filtered by Via. An Asset can appear more than once when the user reaches it in more than one way, for example directly and through its Organization.

A Global Role reaches every Asset and Organization its permissions allow, so it is listed once in the summary rather than as one row per object.

## A Group's Overview

A Group's page opens on its **Overview** tab, which shows the Group's members count and what the Group reaches in its own right: its Global Role, its Configuration Permissions, and its Organizations and Assets, with the same Via column. Every member of the Group receives this access through it. When the Group holds a Global Role, the Overview says that the Group has instance-wide access.

## Preview a Role

When **View As User** is turned on, the Access tab also shows **Preview Role**. Choose a Role and an Organization or an Asset, and click **Preview** to see what that Role would reach there and the permissions the Role carries. Nothing is granted and no user is created.

## API

These pages read endpoints of the DefectDojo Pro UI and are not part of the public API.
