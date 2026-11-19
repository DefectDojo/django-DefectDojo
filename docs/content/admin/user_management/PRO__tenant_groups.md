---
title: "Tenant Groups"
description: "Switch between the tenants of a tenant group, read them all at once, and manage the group's invites and master members"
audience: pro
weight: 5
---

A **tenant group** is a set of DefectDojo Pro tenants run together, each with its own data and its own address. The group's **master** holds the people who work across the tenants: its **master members**. This page covers what a master member sees in the application.

Everything here appears only on an instance that belongs to a tenant group with a master, and only to master members. Everyone else, and every instance outside a tenant group, sees none of it.

## Master roles

A master member holds one of three roles:

* **Admin** reads every tenant of the group, and manages the group's invites and master members.
* **Writer** and **Reader** read only the tenants where they also hold a role, with the weaker of the two roles.

## Switching tenants

The **Switch Tenant** control sits in the sidebar rail, under the Production and Sandbox switch. It shows where you are: the name of the current tenant, or **All Tenants** in the global view. Open it to:

* choose **All Tenants** to read every tenant you can reach at once (see [The global view](#the-global-view)),
* choose a tenant to open it on its own address,
* choose **Manage Tenants** to open the Tenants page.

A tenant in another region is marked **Read-Only**. A tenant that is not active (for example in maintenance or archived) shows its state and cannot be chosen.

## The global view

In the global view, a banner reads **Viewing All Tenants** with a **Back to This Tenant** button, and every list shows the rows of every tenant you can read, with a **Tenant** column naming each row's tenant.

The global view only reads. A list's own actions, such as **New** or **Import**, and the add action of an empty list, open **Select a Tenant** instead: choose a tenant and the same page opens in that tenant, where the change is made. Only active tenants that are not Read-Only are offered.

A list that the global view cannot read yet shows the reason in place of its rows.

## The Tenants page

Master members open it under **Settings > Users & Permissions > Tenants**, or from **Manage Tenants** in the switcher. It lists the group's tenants with their state, region and address. Admins also see two more sections: **Invites** and **Master Members**.

### Invites

People join a tenant, or the master, by invite:

1. Click **New Invite**.
2. Enter the **Email Address** of the person invited. Only an account with exactly this address can accept the invite.
3. Choose the **Tenant** the invite joins, or leave it empty to invite a master member.
4. Choose the **Role**: for a tenant, the role the person holds there (Reader, Writer, or Owner for Admin); for the master, the master role.
5. Click **Submit**. The invite token is shown once: copy it and send it to the person. It is not shown again.

The invite is accepted once, within seven days. **Revoke** stops its token from working at once.

### Master Members

The master members, with their roles. An Admin can **Change Role** or **Remove** a member. A removed member loses the global view at once; their accounts in each tenant stay.

## Through the API

The same actions are available to automation on `/api/v2/tenancy/`, with a token or a session:

* `GET /api/v2/tenancy/context/`: the group, the current tenant (null in the global view), the region and your master role.
* `GET /api/v2/tenancy/tenants/`: the tenants you can read, for master members.
* `POST` and `DELETE /api/v2/tenancy/global_mode/`: enter and leave the global view for the session.
* `/api/v2/tenancy/invites/` and `/api/v2/tenancy/master_members/`: invites and master members, for Admins. `POST /api/v2/tenancy/invites/accept/` accepts an invite with its token.
