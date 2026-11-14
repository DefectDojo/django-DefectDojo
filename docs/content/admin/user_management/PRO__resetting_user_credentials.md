---
title: "Resetting User Credentials in Bulk"
description: "Rotate API tokens, force password resets, and activate and invite many users at once from the Users list"
audience: pro
weight: 2
---

The **Users** list lets you rotate API tokens, force password resets, and activate and invite many users at once. Use it for periodic credential hygiene, after a suspected credential exposure, or to let migrated users sign in.

These bulk actions are available only to **Superusers** and users with the **Global Owner** role. **Activate and Invite** also needs the permission to change users, the same right as the user edit form. If you don't have one of those, the selection checkboxes and bulk buttons do not appear.

## Selecting users

On the **Users** list, use the checkboxes to select one or more users. A bulk-action bar appears with **Reset API Tokens**, **Force Password Reset**, **Activate and Invite** and **Deactivate Users**. Each action asks you to confirm in a dialog before it runs.

The action applies to the users you have explicitly checked. You **cannot include your own account** in a bulk reset: if your account is among the selected rows, the bulk buttons are disabled and a warning is shown.

## Reset API Tokens

**Reset API Tokens** rotates the API token of each selected user: DefectDojo deletes the user's existing token and issues a new one. **The user's current token stops working immediately**, so any scripts or integrations using the old token must be updated with the new one.

* The new token values are **not** shown to you as the admin. Each affected user receives an **"API Token Reset"** notification telling them to retrieve their new token from the UI (delivered according to that user's notification settings).
* [Service users](../pro__service_users/) are skipped and listed in the result. Their tokens are rotated from the Service Users page or the API, where the new token is shown once.
* The action is offered only while API tokens are enabled on the instance (`DD_API_TOKENS_ENABLED`). The same goes for **Force Token Reset** in a single user's menu.

## Force Password Reset

**Force Password Reset** sets the *force-password-reset-on-next-login* flag on each selected user. The next time that user makes a request, DefectDojo redirects them to the **Change Password** page and won't let them continue until they set a new password. The flag clears automatically once they do. A user who has not accepted the current [End User License Agreement](../pro__eula_acceptance/) accepts it on the same page, with a checkbox below the password fields.

Keep in mind what this action does **not** do:

* It does **not** set or randomize a temporary password, and it does **not** return any credentials to you.
* It does **not** send the affected users an email or notification. Because there's no automatic notice, tell the affected users out-of-band that they'll be prompted to change their password on next login.

> **SSO users:** The single-user edit form disables the force-reset flag for SSO-authorized accounts. **Force Password Reset** in bulk sets the flag on **every** selected user, however that user signs in. SSO users sign in through your Identity Provider, so a forced password reset does nothing for them. Do not include SSO-only users in the selection. **Activate and Invite** skips SSO users on its own. The next section explains how.

## Activate and Invite

**Activate and Invite** gives a migrated user a way to sign in. A migration creates its users inactive, with no password. For each selected user, DefectDojo Pro does the following:

* It activates the user, if the user is inactive. Each active user takes a license seat.
* It emails a migrated user a link to set a password, if the user has no password. A user that no migration created gets no link.
* If SSO or LDAP sign-in is on, it sends no link. The users sign in with SSO or LDAP.
* It sends no link to a user that has no password and signed in before. That user signs in with SSO.
* It skips service users, and it skips every account that is already active.
* A Global Owner cannot activate a superuser. The action skips the superuser.

If an email cannot go out, the **Pass On These Links** window lists the user. It shows the link and a copy button. Send each link only to its user, because a link works like a password. [How Migrated Users Sign In](/get_started/pro/onprem/migrating_from_open_source/#how-migrated-users-sign-in) gives the full steps.
