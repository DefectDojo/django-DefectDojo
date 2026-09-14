---
title: "GitLab"
description: "Configure GitLab SSO in DefectDojo Pro"
weight: 80
audience: pro
---

DefectDojo Pro supports login via GitLab (SaaS or self-hosted) over OAuth 2.0. Open-source DefectDojo does not include SSO — see [Authorized Users](/admin/user_management/os__authorized_users/) for open-source access control.

## Callback URL

GitLab needs the exact redirect URI DefectDojo listens on after a user authenticates. It is your DefectDojo base URL followed by `/complete/gitlab/`:

```
https://<your-instance>.cloud.defectdojo.com/complete/gitlab/
```

On-premise, replace the host with your own DefectDojo base URL, keeping the `/complete/gitlab/` path. Register it as the **Redirect URI** on the GitLab application.

## Prerequisites

Complete the following steps in GitLab before configuring DefectDojo:

1. Open your GitLab **User Settings > Applications** (or a Group/Instance application for shared use):
   - GitLab.com: `https://gitlab.com/-/user_settings/applications`
   - Self-hosted: `https://your-gitlab-host/-/user_settings/applications`

2. Add a new application:
   - **Name:** `DefectDojo`
   - **Redirect URI:** the [Callback URL](#callback-url) above.
   - **Scopes:** select `read_user` and `openid` (DefectDojo requests `read_user`, `openid`, `read_api`, and `read_repository`).

3. Save the application and note the **Application ID** and **Secret**.

## Configuration

In DefectDojo, go to **Enterprise Settings > OAuth Settings**, select **GitLab**, and fill in the form:

- **GitLab OAuth Key** — enter your **Application ID**.
- **GitLab OAuth Secret** — enter your **Secret**.
- **GitLab API URL** — the base URL of your GitLab instance, e.g. `https://gitlab.com` (must be a valid URL).

Check **Enable GitLab OAuth** and submit the form. A **Login With GitLab** button will appear on the login page.

Use **Validate Config** at any point to check the settings without saving them. It confirms the settings are complete, checks that the GitLab API URL is reachable, and echoes the exact **redirect URI** to register at GitLab.

## First login and default access

A user provisioned without any group membership lands with **no permissions**. To give every new SSO user a baseline, set a **Default group** and **Default group role** on the System Settings page — see [Default access for SSO-provisioned users](/admin/sso/pro__saml/#default-access-for-sso-provisioned-users). GitLab OAuth login does not synchronize GitLab groups into DefectDojo groups.

## Troubleshooting

**Login fails immediately after the GitLab prompt.** A redirect-URI mismatch — confirm the GitLab application's **Redirect URI** is exactly the [Callback URL](#callback-url), including the trailing slash.

**The form is rejected on save.** The **GitLab API URL** is not a valid URL. Include the scheme, e.g. `https://gitlab.com`.

**Self-hosted GitLab is unreachable in Validate Config.** DefectDojo must be able to reach the GitLab API URL over the network. If your instance restricts outbound traffic, allow the GitLab host.

**Start with Diagnostics.** Rejected sign-ins are recorded under **Connect > Diagnostics** with the reason each was refused.
