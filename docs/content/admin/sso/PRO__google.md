---
title: "Google Auth"
description: "Configure Google OAuth in DefectDojo Pro"
weight: 90
audience: pro
---

DefectDojo Pro supports login via Google accounts over OAuth 2.0. New users are created automatically on first login if they don't already exist, and existing DefectDojo users are matched to Google accounts by username (the portion before the `@` in their Google email). Open-source DefectDojo does not include SSO — see [Authorized Users](/admin/user_management/os__authorized_users/) for open-source access control.

## Callback URL

Google needs the exact redirect URI DefectDojo listens on after a user authenticates. It is your DefectDojo base URL followed by `/complete/google-oauth2/`:

```
https://<your-instance>.cloud.defectdojo.com/complete/google-oauth2/
```

On-premise, replace the host with your own DefectDojo base URL, keeping the `/complete/google-oauth2/` path. Register it under **Authorized redirect URIs** on the OAuth client.

## Prerequisites

Complete the following steps in the Google Cloud Console before configuring DefectDojo:

1. Sign in to the [Google Cloud Console](https://console.cloud.google.com/) and select or create a project.

2. Go to **APIs & Services > Credentials > Create Credentials > OAuth client ID**.

3. Select **Web application** as the application type and give it a descriptive name (e.g. `DefectDojo`).

4. Under **Authorized redirect URIs**, add the [Callback URL](#callback-url) above.

5. Create the client and note the **Client ID** and **Client secret**.

## Configuration

In DefectDojo, go to **Enterprise Settings > OAuth Settings**, select **Google**, and fill in the form:

- **Google OAuth Key** — enter your **Client ID**.
- **Google OAuth Secret** — enter your **Client secret**.
- **Whitelisted Domains** — enter one or more email-address domains (e.g. `yourcompany.com`) allowed to sign in. **Comma-separated, with no spaces.**
- **Whitelisted Email Addresses** — alternatively, enter specific addresses allowed to sign in (e.g. `user1@yourcompany.com,user2@yourcompany.com`). **Comma-separated, with no spaces.**

You must set at least one whitelisted domain or email address, or no one will be able to sign in via Google — Google will authenticate the account, but DefectDojo rejects any address not on a whitelist.

Check **Enable Google OAuth** and submit the form. A **Login With Google** button will appear on the login page.

Use **Validate Config** at any point to check the settings without saving them. It confirms the settings are complete, fetches the Google discovery document, checks that at least one whitelist entry is set, and echoes the exact **redirect URI** to register at Google.

## First login and default access

A user provisioned without any group membership lands with **no permissions**. To give every new SSO user a baseline, set a **Default group** and **Default group role** on the System Settings page — see [Default access for SSO-provisioned users](/admin/sso/pro__saml/#default-access-for-sso-provisioned-users). Google login does not synchronize Google Workspace groups into DefectDojo groups.

## Troubleshooting

**Everyone is rejected even though the Google prompt succeeds.** No whitelist is set, or the address is not on it. Add the user's domain to **Whitelisted Domains** or their address to **Whitelisted Email Addresses**, comma-separated with no spaces.

**Login fails immediately after the Google prompt.** A redirect-URI mismatch — confirm **Authorized redirect URIs** contains the exact [Callback URL](#callback-url).

**Start with Diagnostics.** Rejected sign-ins are recorded under **Connect > Diagnostics** with the reason each was refused.
