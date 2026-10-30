---
title: "View As User"
description: "See DefectDojo the way another user sees it, read-only and audited"
audience: pro
weight: 4
---

**View As User** shows the application as another user sees it: the same pages, lists, counts and menus that user would get. It is meant for checking access before and after a change, for example before a new team is onboarded. The view is read-only, lasts at most an hour, and every start and stop is written to the Audit Log.

View As User is a beta feature and is off by default. A Superuser turns it on under **Settings > Feature Flags**.

## Who can view as whom

The **View As** button appears on a user's page when you may view as that user:

* A Superuser, or a user who holds the permission to edit users, may view as any user.
* A user who can manage the members of a Group (the Manage Members permission of their own Role in that Group) may view as any member of that Group.

In every case:

* The user being viewed may not be a Superuser, and may not be inactive.
* You must already be able to see everything that user can see. If they can see Organizations or Assets that you cannot, the button is disabled and its tooltip says how many, for example "You cannot view as this user: they can see 3 assets you cannot."
* You cannot view as yourself, and a View As session cannot be started from inside another one.
* Service users cannot start View As. A service user can be viewed as, which shows what its token can reach.

## While viewing as a user

1. Open the user's page and click **View As**. A group lead who cannot open users' pages starts it from the group instead: on the group's **Members** tab, choose the member under **View As a Member** and click **View As**.
2. The application reloads as that user. A bar across the top of the page reads "Viewing as <name>. Read-only." with an **Exit** button.

While the bar is shown:

* Everything is read-only. Controls that would change data are hidden or disabled, and a change sent anyway is refused with "Read-only while viewing as <name>."
* Sign-in credentials are not available: the user's API token, MFA settings and recovery codes cannot be read while viewing as them.
* Walkthroughs are turned off, since they record progress.
* Only the Pro UI is affected. API requests made with an API token, and the Classic UI, still act as you.
* In the last ten minutes the bar shows the time left.

## Ending View As

The session ends when you click **Exit**, when you sign out, or after one hour. **Exit** returns you to the user's page as yourself.

## Audit Log

Each session is recorded as a **View As Session** in the Audit Log: one entry when it starts, naming the actor and the user viewed, and one when it ends, with how it ended (**Exit**, **Logout**, **Expired** or **Revoked**). A session is revoked when the viewed user becomes a Superuser or is deactivated, when View As User is turned off, or when you no longer pass the rules above (they are checked again every minute while the session runs).
