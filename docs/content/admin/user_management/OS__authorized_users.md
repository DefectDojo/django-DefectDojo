---
title: "Open-Source Permissions"
description: "How access to Assets and Organizations is granted in open-source DefectDojo"
weight: 1
audience: opensource
---

Open-source DefectDojo controls access to Assets and Organizations with the **Authorized Users** model. Each Asset and Organization has an Authorized Users panel listing the people who can see that record and the data nested under it.

If you're running DefectDojo Pro, this article doesn't apply to your installation — Pro uses a richer role-based system covered in [Permissions in DefectDojo](../about_perms_and_roles/).

## How access is granted

There are two lists, and a user only needs to appear on one of them to gain access:

- **An Asset's Authorized Users list** grants access to that single Asset, plus everything nested underneath it (its Engagements, Tests, Findings, and Endpoints).
- **An Organization's Authorized Users list** grants access to the Organization itself **and cascades to every Asset underneath it**. A user who is authorized on an Organization does not need to also be added to each child Asset — they are already covered.

There are no roles, no groups, and no global roles. A user is either on the list (or is a superuser/staff member — see below), or they cannot see the Asset.

## Superusers and staff bypass the lists

Users marked as **superuser** or **staff** in DefectDojo can see and act on every Asset and Organization regardless of the Authorized Users lists. The lists exist to grant access to non-staff users; they do not restrict staff or superusers.

The first account created on a fresh DefectDojo installation is automatically a superuser.

## Who can edit the lists

Only **superuser** or **staff** users see the controls to add or remove people from an Authorized Users panel. Everyone else who has access to an Asset or Organization sees the panel as a read-only roster — useful for finding out who else is on the team, but not for changing membership.

## Where the panel lives

The Authorized Users panel appears on two pages in the classic UI:

- The **Asset detail page** has an Authorized Users panel for that Asset. It supports two actions for staff users:
  - **Add a user to the Asset's Authorized Users list**
  - **Remove a user from the Asset's Authorized Users list**
- The **Organization detail page** has an Authorized Users panel for that Organization, with the corresponding two actions:
  - **Add a user to the Organization's Authorized Users list**
  - **Remove a user from the Organization's Authorized Users list**

When you remove a user from an Organization's list, the cascade is removed too — they lose access to every child Asset unless they're still on a specific Asset's list, or they're a staff/superuser.

## Choosing between Asset and Organization access

A few rules of thumb:

- If a person should see every Asset under a category (for example, every Asset owned by a particular team), put them on the **Organization** list and let the cascade take care of the rest.
- If a person should only see one specific Asset, put them on that **Asset**'s list.
- If you find yourself adding the same person to many individual Assets under one Organization, that's a signal you should add them to the Organization instead.

## Coming from a previous version of DefectDojo

DefectDojo open-source moved back to the Authorized Users model in version 3.0. If you're upgrading from a release that had the Members / Groups / Global Roles system, your existing access is carried forward into Authorized Users automatically by the upgrade — no manual mapping is needed.

The upgrade ships with a read-only management command, `preview_legacy_authorization_migration`, that summarizes what an upgrade would change against a copy of your database. The recommended workflow is to install 3.0 in a staging environment with a snapshot of production, run the command, review the summary, and then upgrade production.

If you're moving the other direction — from open-source to DefectDojo Pro — Pro ships a `reconcile_authorized_users_to_rbac` command that brings Authorized Users access forward into Pro's RBAC. It supports `--dry-run` and is idempotent.

For more detail on both paths, see the [3.0 upgrade notes](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization).
