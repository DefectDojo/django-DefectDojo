---
title: "Multi-Factor Authentication (MFA)"
description: "Set up MFA on your own account, require it across your instance, and recover a user who has lost their device"
audience: pro
weight: 3
---

Multi-factor authentication adds a second step to login: after your password, DefectDojo asks for a six-digit code from an authenticator app. We strongly recommend requiring it for every user on instances that are not behind SSO.

DefectDojo Pro's MFA uses a **TOTP authenticator app** — Google Authenticator, 1Password, Authy, or any other app that scans a standard QR code. There is no email or SMS option.

## Setting up MFA on your account

1. Go to **Connect \> Authorization \> MFA Settings**.
2. Under **Personal Multi-Factor Authentication Settings**, click **Set Up MFA**.
3. Scan the QR code with your authenticator app. If you cannot scan it, the setup screen also shows the key as text, which you can type into your app by hand.
4. Enter the six-digit code your app displays, and click **Verify & enable**.
5. DefectDojo shows your **recovery codes**. Save them somewhere safe before continuing — see below. Click **Copy codes**, store them, then click **I've saved them. Continue**.

MFA is active from that point on. The next time you log in, DefectDojo will ask for a code after your password.

### Recovery codes

You are issued **ten single-use recovery codes** when you enable MFA. Each one can be used once, in place of a code from your authenticator app, and is consumed when used.

They are shown **once**, on the final setup screen. The MFA Settings page afterwards shows only how many you have left, not the codes themselves.

If you lose your recovery codes — or want a fresh set after using several — click **Regenerate Recovery Codes** on the MFA Settings page. This **replaces all of your existing codes**: any you saved previously stop working immediately, so save the new set right away.

Recovery codes are what let you get back in when you lose your phone, so store them somewhere separate from the device running your authenticator app.

### Turning MFA off

**Disable MFA** on the MFA Settings page turns it off for your own account. You are asked to confirm with a code first: either the current six-digit code from your authenticator app, or one of your unused recovery codes. Being logged in is not enough on its own.

That is deliberate. Removing MFA also deletes your recovery codes, so an attacker who got hold of a logged-in session could otherwise strip the second factor and keep access to the account. Requiring the factor in order to remove it means they need your authenticator, not just your session.

DefectDojo notifies you when MFA is removed from your account, so if it happens without you doing it, you will hear about it.

If your administrator has made MFA mandatory, you will be prompted to set it up again on your next login.

## Logging in with MFA

After entering your username and password, DefectDojo asks for your six-digit code. If you do not have your authenticator app, enter one of your **recovery codes** in the same field instead — that code is then used up.

## Requiring MFA for everyone

Superusers can make MFA mandatory across the instance:

1. Go to **Connect \> Authorization \> MFA Settings**.
2. In the **MFA Settings** card — visible only to Superusers — tick **Require Multi-Factor Authentication Globally**.
3. Submit.

This is **off by default**.

Once it is on, any user who has not yet enrolled is sent to the MFA setup screen when they next log in, and **cannot skip it**. They finish enrollment, save their recovery codes, and land where they were originally headed.

### SSO users

MFA is enforced by DefectDojo, not delegated to your identity provider. With global MFA required, users who sign in through SSO are also sent to set up MFA after their provider returns them to DefectDojo, and are prompted for a code on subsequent logins.

There is no setting to exempt SSO users. If your identity provider already enforces its own MFA, decide deliberately whether you want both — turning global MFA on will mean two prompts for SSO users.

## Recovering a user who has lost their MFA device

Work through these in order:

1. **Use a recovery code.** If the user still has their recovery codes, they enter one instead of an app code at login, then set MFA up again from scratch.
2. **If they still have an unused recovery code,** they can go to **MFA Settings**, click **Disable MFA**, and enter that recovery code to confirm, then re-enroll. Being logged in is not sufficient by itself; disabling MFA requires a code.
3. **Ask an administrator to clear their MFA.** With server access, an administrator can remove MFA from an account:

   ```
   python manage.py remove_mfa --username <username>
   ```

   The command also accepts `--user-id` or `--email` instead of `--username` (exactly one is required; `--email` is case-insensitive). It asks for confirmation before making the change. The user can then log in with just their password and enroll again.

   This is a shell command, so it needs access to the DefectDojo container or host. There is no equivalent button in the UI or endpoint in the API. On **DefectDojo Cloud**, contact [DefectDojo Support](mailto:support@defectdojo.com) to have it run.

Creating a replacement account is **not** necessary — clearing MFA preserves the user's existing permissions, history, and assignments.

## MFA and the API

When a user has MFA enabled, requests to `/api/v2/api-token-auth/` — the endpoint that exchanges a username and password for an API token — must also include an MFA code, in an `mfa_code` field alongside the credentials. Either a current TOTP code or an unused recovery code is accepted; passing a recovery code here **consumes** it.

A missing or incorrect code returns the same generic *"Unable to log in with provided credentials"* error as a bad password, so if token requests start failing after a user enables MFA, this is the first thing to check.

**Existing API tokens keep working.** Enabling or disabling MFA does not revoke or rotate tokens already issued — the MFA check applies when a token is issued, not on each request made with it. Long-lived automation that already holds a token is unaffected by a user enrolling in MFA.
