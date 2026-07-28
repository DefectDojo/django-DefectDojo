---
title: "Resetting User Credentials in Bulk"
description: "Rotate API tokens and force password resets for many users at once from the Users list"
audience: pro
weight: 2
---

The DefectDojo Pro **Users** list lets you rotate API tokens and force password resets for many users at once — useful for periodic credential hygiene or responding to a suspected credential exposure.

These bulk actions are available only to **Superusers** and users with the **Global Owner** role. If you don't have one of those, the selection checkboxes and bulk buttons do not appear.

## Selecting users

On the **Users** list, use the checkboxes to select one or more users. A bulk-action bar appears with the reset buttons. Each action asks you to confirm in a dialog before it runs.

The action applies to the users you have explicitly checked. You **cannot include your own account** in a bulk reset: if your account is among the selected rows, the bulk buttons are disabled and a warning is shown.

## Reset API Tokens

**Reset API Tokens** rotates the API token of each selected user: DefectDojo deletes the user's existing token and issues a new one. **The user's current token stops working immediately**, so any scripts or integrations using the old token must be updated with the new one.

* The new token values are **not** shown to you as the admin. Each affected user receives an **"API Token Reset"** notification telling them to retrieve their new token from the UI (delivered according to that user's notification settings).

## Force Password Reset

**Force Password Reset** sets the *force-password-reset-on-next-login* flag on each selected user. The next time that user makes a request, DefectDojo redirects them to the **Change Password** page and won't let them continue until they set a new password. The flag clears automatically once they do.

Keep in mind what this action does **not** do:

* It does **not** set or randomize a temporary password, and it does **not** return any credentials to you.
* It does **not** send the affected users an email or notification. Because there's no automatic notice, tell the affected users out-of-band that they'll be prompted to change their password on next login.

> **SSO users:** Unlike the single-user edit form (which disables the force-reset flag for SSO-authorized accounts), the bulk action applies the flag to **every** selected user regardless of how they authenticate. Since SSO users sign in through your Identity Provider rather than a DefectDojo password, forcing a password reset on them is generally not meaningful — avoid including SSO-only users in the selection.
