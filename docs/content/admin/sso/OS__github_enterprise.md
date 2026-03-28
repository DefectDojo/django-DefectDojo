---
title: "GitHub Enterprise"
description: "Configure GitHub Enterprise SSO in Open-Source DefectDojo"
weight: 8
audience: opensource
---

Open-Source DefectDojo supports login via GitHub Enterprise. DefectDojo Pro users should refer to the [Pro GitHub Enterprise guide](/admin/sso/pro__github_enterprise/).

## Prerequisites

Complete the following steps in GitHub Enterprise before configuring DefectDojo:

1. [Create a new OAuth App](https://docs.github.com/en/enterprise-server/developers/apps/building-oauth-apps/creating-an-oauth-app) in your GitHub Enterprise Server.

2. Choose a name for the application, e.g. `DefectDojo`.

3. Set the **Redirect URI**:
   `https://your-dojo-host:your-port/complete/github-enterprise/`

4. Note the **Client ID** and **Client Secret** from the app.

## Configuration

Set the following as environment variables, or without the `DD_` prefix in your `local_settings.py` file (see [Configuration](/get_started/open_source/configuration/)):

{{< highlight python >}}
DD_SOCIAL_AUTH_GITHUB_ENTERPRISE_KEY=(str, 'YOUR_CLIENT_ID'),
DD_SOCIAL_AUTH_GITHUB_ENTERPRISE_SECRET=(str, 'YOUR_CLIENT_SECRET'),
DD_SOCIAL_AUTH_GITHUB_ENTERPRISE_URL=(str, 'https://github.yourcompany.com/'),
DD_SOCIAL_AUTH_GITHUB_ENTERPRISE_API_URL=(str, 'https://github.yourcompany.com/api/v3/'),
DD_SOCIAL_AUTH_GITHUB_ENTERPRISE_OAUTH2_ENABLED=True,
{{< /highlight >}}

Restart DefectDojo. A **Login with GitHub Enterprise** button will appear on the login page.
