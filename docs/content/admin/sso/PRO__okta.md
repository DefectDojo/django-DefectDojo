---
title: "Okta"
description: "Configure Okta SSO in DefectDojo Pro"
weight: 110
audience: pro
---

DefectDojo Pro supports login via Okta over OAuth 2.0. Open-source DefectDojo does not include SSO — see [Authorized Users](/admin/user_management/os__authorized_users/) for open-source access control.

## Callback URL

Okta needs the exact redirect URI DefectDojo listens on after a user authenticates. It is your DefectDojo base URL followed by `/complete/okta-oauth2/`:

```
https://<your-instance>.cloud.defectdojo.com/complete/okta-oauth2/
```

On-premise, replace the host with your own DefectDojo base URL, keeping the `/complete/okta-oauth2/` path. Register this value verbatim as a **Sign-in redirect URI** on the Okta application. A mismatch here is the most common cause of a failed Okta login.

## Prerequisites

Complete the following steps in Okta before configuring DefectDojo:

1. Sign in to the Okta Admin Console (or create an account at [Okta](https://www.okta.com/developer/signup/)).

2. Go to **Applications > Applications > Create App Integration**.

3. Choose **OIDC - OpenID Connect** as the sign-in method and **Web Application** as the application type, then continue.

4. Give the app a name (e.g. `DefectDojo`).

5. Under **Sign-in redirect URIs**, add the [Callback URL](#callback-url) above.

6. Under **Assignments**, choose who may use the application (a group, or everyone), then save.

7. From the application's **General** tab, note the **Client ID** and **Client Secret**.

8. From the Admin Console, note your **Okta domain** (the org URL, e.g. `https://your-org.okta.com`). DefectDojo expects this as `https://your-org.okta.com/oauth2` in the configuration below.

## Configuration

In DefectDojo, go to **Enterprise Settings > OAuth Settings**, select **Okta**, and fill in the form:

- **Okta OAuth Key** — enter your **Client ID**.
- **Okta OAuth Secret** — enter your **Client Secret**.
- **Okta API URL** — enter your Org-URL in the format `https://your-org.okta.com/oauth2`.

Check **Enable Okta OAuth** and submit the form. A **Login With Okta** button will appear on the login page.

Use **Validate Config** at any point to check the settings without saving them. It confirms the settings are complete, checks that the Okta endpoint is reachable, and echoes the exact **redirect URI** to register at Okta so you can compare it against what you entered in step 5.

## First login and default access

New users are provisioned automatically on first login (when **Create User on Successful Login** is enabled under **Login Settings**), and existing users are matched by username. A newly provisioned user who is not placed in any group lands on DefectDojo with **no permissions** and an empty dashboard. To give every new SSO user a baseline, set a **Default group** and **Default group role** on the System Settings page — see [Default access for SSO-provisioned users](/admin/sso/pro__saml/#default-access-for-sso-provisioned-users), which applies to every social-auth provider including Okta.

Okta over OAuth does not synchronize Okta group memberships into DefectDojo groups. If you need directory-driven group membership, use [SAML](/admin/sso/pro__saml/) (which supports SAML group mapping) or [SCIM Provisioning](/admin/sso/pro__scim/) (which pushes group membership from Okta).

## Troubleshooting

**The Okta login button does not appear.** The provider is not enabled, or the form was not saved. Enable **Okta OAuth** and submit; the button only appears after both.

**Login fails immediately after the Okta prompt.** Almost always a redirect-URI mismatch. Confirm the **Sign-in redirect URI** on the Okta app is exactly the [Callback URL](#callback-url), including the trailing slash, and matches your DefectDojo base URL.

**"Okta API URL" errors or discovery fails in Validate Config.** The Org-URL is wrong or missing the `/oauth2` suffix. Use `https://your-org.okta.com/oauth2`.

**Start with Diagnostics.** Rejected sign-ins are recorded under **Connect > Diagnostics**, with the reason each was refused. That is usually faster than reading Okta's system log. See [Authorization Connectors](/admin/sso/pro__authorization_connectors/) for the difference between what is configured and why a sign-in failed.
