---
title: "User Management"
description: "Manage users, access control, and authentication in DefectDojo"
summary: ""
date: 2023-09-07T16:06:50+02:00
lastmod: 2023-09-07T16:06:50+02:00
draft: false
weight: 5
chapter: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  robots: "" # custom robot tags (optional)
exclude_search: true
---

DefectDojo's user management surface is different in each edition. Pick the section that matches your installation.

## DefectDojo Open-Source

Open-source DefectDojo uses the **Authorized Users** model: a user is given access to a Product or a Product Type by being added to that record's Authorized Users list. Superusers and staff can see everything.

* [Authorized Users](./os__authorized_users/) — how to grant access to Products and Product Types

Authentication on open-source DefectDojo is local username/password plus the password-reset flow.

## DefectDojo Pro

DefectDojo Pro uses a role-based system with Members, Groups, and Global Roles. Users can also be granted SSO access through SAML or one of the supported OAuth providers.

* [Permissions in DefectDojo](./about_perms_and_roles/) — overview of Roles, Memberships, Global Roles, and Configuration Permissions
* [Set a User's Permissions](./set_user_permissions/) — assigning Roles, Global Roles, and Configuration Permissions
* [Share permissions: User Groups](./create_user_group/) — assigning permissions to many users at once
* [Set Permissions in Pro](./pro_permissions_overhaul/) — Pro-specific UI for managing Members and Permissions
* [Action permission charts](./user_permission_chart/) — full reference of every permission for every Role
* [Single Sign-On](/admin/sso/) — SAML and OAuth setup for Pro

## Migrating between editions

If you're moving from open-source's Authorized Users to Pro's RBAC, or upgrading from a pre-2.59 open-source release that used RBAC into the current Authorized Users model, see the [2.59 upgrade notes](/releases/os_upgrading/2.59/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization). Existing access is preserved automatically.
