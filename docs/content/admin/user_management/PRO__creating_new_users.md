---
title: "Creating a new user"
description: "How to onboard a new user onto your DefectDojo instance"
audience: pro
weight: 1
---

This page describes the recommended onboarding workflow for adding new users to a DefectDojo instance.  For automation (pipelines, scanners), use a [service user](../pro__service_users/) instead: it needs no email address or password and its API token is shown when it is created.

The admin who creates the account is responsible for delivering the initial credentials (username and password) to the new user.

## Recommended workflow

1. **Create the user account** in DefectDojo (Superuser only):
   * Open **Settings > Users & Permissions > Users** and select **New User**.
   * Enter the new user's name and email address.
   * Set a temporary password.
   * Submit the form.

2. **Assign permissions** as appropriate — Asset/Organization membership, Configuration Permissions, Global Role, or Superuser status. See [Set a User's permissions](../set_user_permissions/) for details. A new user with no assignments will not be able to see any Assets or Findings.

3. **Send the credentials to the new user out-of-band** (over email, your team's chat tool, or however you normally share secrets). Include:
   * The DefectDojo instance URL.
   * The username (typically their email address).
   * The temporary password you just set.
   * A note that they should change the password and enable MFA (if your instance uses MFA) on first login.

4. **The new user logs in and rotates the credential.** They can either:
   * Log in with the temporary password and then [change it](#changing-your-own-password) from the account menu or their User Profile, or
   * Use the **I forgot my password** link on the login page to set a password directly without using the temporary one. The temporary password is still required for the initial account record to exist, but the user does not need to remember it if they use the password-reset flow.

5. **The new user configures MFA** from their profile menu. We strongly recommend requiring MFA for all users on instances that aren't behind SSO.

## Changing your own password

Any user who signs in with a DefectDojo password can change it without leaving the Pro UI. Either of these opens the **Change Password** dialog:

* Open the account menu (your username at the bottom of the sidebar) and choose **Change Password**.
* Open **User Profile** and select **Change Password** on the profile card.

Enter your **Current Password**, then the **New Password** and **Confirm New Password**. The change is accepted only when:

* the current password is right. If it is not, the dialog says "Current password is incorrect." and nothing changes;
* the new password differs from the current one, and both new entries match;
* the new password meets the instance's password policy (minimum and maximum length, required character types and the common-password check, set under **System Settings**). A policy message appears under **New Password**.

You stay signed in after the change.

A few safeguards apply:

* **Too many wrong current passwords.** Incorrect current passwords are counted per account against the instance's rate limit (`DD_RATE_LIMITER_RATE`, 5 per minute by default). Once the limit is reached, every attempt is refused with "Too many incorrect current passwords. Try again later." for a while, even with the right password. A new password that only fails the policy does not count against the limit.
* **Multi-factor authentication.** If your account uses MFA, the change is accepted only once the current session has passed the MFA check.
* **Accounts without a password.** **Change Password** is not shown to accounts that sign in through single sign-on or are provisioned through SCIM, because they have no DefectDojo password; change those passwords with your identity provider. An attempt through the API is refused with "This account has no password to change."
* **Forced resets.** When an administrator [forces a password reset](../pro__resetting_user_credentials/#force-password-reset), you are taken to the full-page **Change Password** form at your next request instead, and cannot continue until you set a new password.

## SSO Users

If your instance is configured with [SSO](../configure_sso/), the workflow is different — users are typically created on first login from the Identity Provider, and you only need to grant them group membership or roles afterwards.

## Recovering from a lost MFA token

If a user loses access to their MFA device, they can log in with one of the recovery codes issued when they enrolled. If those are gone too, a Superuser can clear MFA from the account with **Reset MFA** in the user's action menu (or, with server access, `python manage.py remove_mfa --username <username>`), after which the user logs in with their password and enrolls again — their permissions and history are preserved, so there is no need to create a replacement account.

See [Multi-Factor Authentication](../pro__mfa/#recovering-a-user-who-has-lost-their-mfa-device) for the full recovery options, and note that access to the **Cloud Manager** itself is a separate matter — see the [connectivity troubleshooting guide](/get_started/pro/cloud/connectivity-troubleshooting/#ive-lost-access-to-my-mfa-codes).
