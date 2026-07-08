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
   * Enter the new user's name and email address.
   * Set a temporary password.
   * Submit the form.

2. **Assign permissions** as appropriate — Product/Product Type membership, Configuration Permissions, Global Role, or Superuser status. See [Set a User's permissions](../set_user_permissions/) for details. A new user with no assignments will not be able to see any Products or Findings.

3. **Send the credentials to the new user out-of-band** (over email, your team's chat tool, or however you normally share secrets). Include:
   * The DefectDojo instance URL.
   * The username (typically their email address).
   * The temporary password you just set.
   * A note that they should change the password and enable MFA (if your instance uses MFA) on first login.

4. **The new user logs in and rotates the credential.** They can either:
   * Log in with the temporary password and then change it from their profile menu, or
   * Use the **I forgot my password** link on the login page to set a password directly without using the temporary one. The temporary password is still required for the initial account record to exist, but the user does not need to remember it if they use the password-reset flow.

5. **The new user configures MFA** from their profile menu. We strongly recommend requiring MFA for all users on instances that aren't behind SSO.

## SSO Users

If your instance is configured with [SSO](../configure_sso/), the workflow is different — users are typically created on first login from the Identity Provider, and you only need to grant them group membership or roles afterwards.

If you have moved to open-source DefectDojo (where SSO is Pro-only) and existing SSO users can no longer log in, see [Re-enabling login for SSO users](../os__sso_user_local_login_fallback/).

## Recovering from a lost MFA token

If a user loses access to their MFA device, see the [MFA recovery section](/get_started/pro/cloud/connectivity-troubleshooting/#ive-lost-access-to-my-mfa-codes) of the connectivity troubleshooting guide. There is currently no way to remove MFA from an account without an MFA code — the workaround is to create a new account for the user and re-grant the same permissions.
