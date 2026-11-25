---
title: "Creating a new user"
description: "How to onboard a new user onto your DefectDojo instance"
audience: opensource
weight: 1
---

This page describes the recommended onboarding workflow for adding new users to a DefectDojo instance.  DefectDojo users can be used as both standard, human-operated accounts and as service accounts.

The admin who creates the account is responsible for delivering the initial credentials (username and password) to the new user.

## Recommended workflow

1. **Create the user account** in DefectDojo (Superuser only):
   * Navigate to **👤 Users → Users** to open the All Users table.
   * Click the 🛠️ (crossed wrench and screwdriver) icon.
   * Enter the new user's name and email address. The address must not already belong to another account (compared ignoring case).
   * Set a temporary password.
   * Submit the form.

2. **Grant access** as appropriate. Add the user to the Authorized Users list of each Asset or Organization they need, or mark them as staff or superuser. See [Open-Source Permissions](../os__authorized_users/) for details. A new user with no assignments will not be able to see any Assets or Findings.

3. **Send the credentials to the new user out-of-band** (over email, your team's chat tool, or however you normally share secrets). Include:
   * The DefectDojo instance URL.
   * The username (typically their email address).
   * The temporary password you just set.
   * A note that they should change the password on first login.

4. **The new user logs in and rotates the credential.** They can either:
   * Log in with the temporary password and then change it from their profile menu, or
   * Use the **I forgot my password** link on the login page to set a password directly without using the temporary one. The temporary password is still required for the initial account record to exist, but the user does not need to remember it if they use the password-reset flow.

## Users who signed in with SSO

Open-source DefectDojo supports local accounts only. SSO (SAML, OIDC, OAuth), LDAP, and MFA are available in [DefectDojo Pro](/admin/sso/).

If you have upgraded to open-source DefectDojo 3.x and existing SSO users can no longer log in, see [Re-enabling login for SSO users](../os__sso_user_local_login_fallback/).

## Email addresses

An account's email address is where password resets are sent, so DefectDojo treats it as part of who the account is:

* **A new email address must be unique.** Creating a user, editing a user and editing your own profile, through the UI or the API, refuse an address another account already uses, compared ignoring case. Accounts that already share an address are not changed: they keep signing in and can still edit everything else.
* **An administrator changes any user's email address** from the user's page or the API, subject to the rule above.
* **Users change their own email address only by proving they own the new one.** With `DD_EMAIL_CHANGE_CONFIRMATION_ENABLED=True`, changing the email on **Profile** sends a confirmation link to the new address, and the account keeps its old address until the link is opened. The link works once, only for the account that asked for it, and expires after `DD_PASSWORD_RESET_TIMEOUT` (3 days by default). This needs a working mail server in `DD_EMAIL_URL`.
* **With the setting off (the default)**, users cannot change their own email address on **Profile**; an administrator changes it for them. DefectDojo does not ship a mail server, so this is the safe default.
* **The user API (v2 and v3) does not change your own email address** unless you are a superuser, even if you hold the permissions to manage users: it saves at once and sends no link, so it answers `400` with an `email` error. Change your own address on **Profile**.
* **Users who sign in through single sign-on** never change their own email address: it comes from the identity provider.
