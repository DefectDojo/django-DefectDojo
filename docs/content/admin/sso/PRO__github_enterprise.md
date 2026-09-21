---
title: "GitHub Enterprise"
description: "Configure GitHub Enterprise SSO in DefectDojo Pro"
weight: 70
audience: pro
---

DefectDojo Pro supports login via GitHub Enterprise Server over OAuth 2.0. Open-source DefectDojo does not include SSO — see [Authorized Users](/admin/user_management/os__authorized_users/) for open-source access control.

## Callback URL

GitHub Enterprise needs the exact redirect URI DefectDojo listens on after a user authenticates. It is your DefectDojo base URL followed by `/complete/github-enterprise/`:

```
https://<your-instance>.cloud.defectdojo.com/complete/github-enterprise/
```

On-premise, replace the host with your own DefectDojo base URL, keeping the `/complete/github-enterprise/` path. Register it as the **Authorization callback URL** on the OAuth app.

## Prerequisites

Complete the following steps in your GitHub Enterprise Server before configuring DefectDojo:

1. [Create a new OAuth App](https://docs.github.com/en/enterprise-server/developers/apps/building-oauth-apps/creating-an-oauth-app) (**Settings > Developer settings > OAuth Apps > New OAuth App**).

2. Choose a name (e.g. `DefectDojo`) and set the **Homepage URL** to your DefectDojo base URL.

3. Set the **Authorization callback URL** to the [Callback URL](#callback-url) above.

4. Register the app, then note the **Client ID** and generate and note a **Client secret**.

## Configuration

In DefectDojo, go to **Enterprise Settings > OAuth Settings**, select **GitHub Enterprise**, and fill in the form:

- **GitHub Enterprise OAuth Key** — enter your **Client ID**.
- **GitHub Enterprise OAuth Secret** — enter your **Client secret**.
- **GitHub Enterprise URL** — your GitHub Enterprise base URL, e.g. `https://github.yourcompany.com/`.
- **GitHub Enterprise API URL** — your GitHub Enterprise API URL, e.g. `https://github.yourcompany.com/api/v3/`.

Both URL fields must be valid URLs; DefectDojo rejects the form otherwise. Check **Enable GitHub Enterprise OAuth** and submit. A **Login With GitHub** button will appear on the login page.

Use **Validate Config** at any point to check the settings without saving them. It confirms the settings are complete, checks that the GitHub Enterprise URL and API URL are reachable, and echoes the exact **redirect URI** to register at GitHub.

## First login and default access

A user provisioned without any group membership lands with **no permissions**. To give every new SSO user a baseline, set a **Default group** and **Default group role** on the System Settings page — see [Default access for SSO-provisioned users](/admin/sso/pro__saml/#default-access-for-sso-provisioned-users). GitHub Enterprise login does not synchronize GitHub organizations or teams into DefectDojo groups.

## Troubleshooting

**The form is rejected on save.** The **URL** or **API URL** is not a valid URL. Include the scheme (`https://`) and, for the API URL, the `/api/v3/` path.

**Login fails immediately after the GitHub prompt.** A callback-URL mismatch — confirm the OAuth app's **Authorization callback URL** is exactly the [Callback URL](#callback-url).

**Start with Diagnostics.** Rejected sign-ins are recorded under **Connect > Diagnostics** with the reason each was refused.
