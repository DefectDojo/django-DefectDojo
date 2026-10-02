---
title: "Auth0"
description: "Configure Auth0 SSO in DefectDojo Pro"
weight: 50
audience: pro
---

DefectDojo Pro supports login via Auth0 over OAuth 2.0. Open-source DefectDojo does not include SSO — see [Authorized Users](/admin/user_management/os__authorized_users/) for open-source access control.

## Callback URL

Auth0 needs the exact redirect URI DefectDojo listens on after a user authenticates. It is your DefectDojo base URL followed by `/complete/auth0/`:

```
https://<your-instance>.cloud.defectdojo.com/complete/auth0/
```

On-premise, replace the host with your own DefectDojo base URL, keeping the `/complete/auth0/` path. Register it under the application's **Allowed Callback URLs**.

## Prerequisites

Complete the following steps in your Auth0 dashboard before configuring DefectDojo:

1. Create a new application: **Applications > Create Application > Regular Web Application**.

2. On the application's **Settings** tab, set **Allowed Callback URLs** to the [Callback URL](#callback-url) above.

3. Note the following values — you will need them in DefectDojo:
   - **Domain**
   - **Client ID**
   - **Client Secret**

## Configuration

In DefectDojo, go to **Enterprise Settings > OAuth Settings**, select **Auth0**, and fill in the form:

- **Auth0 OAuth Key** — enter your **Client ID**.
- **Auth0 OAuth Secret** — enter your **Client Secret**.
- **Auth0 Domain** — enter your **Domain** (e.g. `your-tenant.us.auth0.com`).

Check **Enable Auth0 OAuth** and submit the form. (The Enable checkbox unlocks once the key and secret are filled in.) A **Login With Auth0** button will appear on the login page.

Use **Validate Config** at any point to check the settings without saving them. It confirms the settings are complete, fetches the Auth0 discovery document for your domain, and echoes the exact **redirect URI** to register at Auth0.

## First login and default access

New users are provisioned automatically on first login (when **Create User on Successful Login** is enabled under **Login Settings**), and existing users are matched by username. A user provisioned without any group membership lands with **no permissions**. To give every new SSO user a baseline, set a **Default group** and **Default group role** on the System Settings page — see [Default access for SSO-provisioned users](/admin/sso/pro__saml/#default-access-for-sso-provisioned-users).

Auth0 login does not synchronize Auth0 roles or groups into DefectDojo groups. For directory-driven group membership use [SAML](/admin/sso/pro__saml/) or the generic [OIDC](/admin/sso/pro__oidc/) provider (Auth0 can act as an OIDC provider).

## Troubleshooting

**The Auth0 login button does not appear.** Enable and save the provider; the Enable checkbox also requires the key and secret to be present first.

**Login fails immediately after the Auth0 prompt.** A callback-URL mismatch — confirm **Allowed Callback URLs** contains the exact [Callback URL](#callback-url), including the trailing slash.

**Discovery fails in Validate Config.** The **Auth0 Domain** is wrong. Use the tenant domain (e.g. `your-tenant.us.auth0.com`), not the application's URL.

**Start with Diagnostics.** Rejected sign-ins are recorded under **Connect > Diagnostics** with the reason each was refused.
