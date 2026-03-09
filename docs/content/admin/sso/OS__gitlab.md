---
title: "GitLab"
description: "Configure GitLab SSO in Open-Source DefectDojo"
weight: 10
audience: opensource
---

Open-Source DefectDojo supports login via GitLab. DefectDojo Pro users should refer to the [Pro GitLab guide](../PRO__gitlab/).

## Prerequisites

Complete the following steps in GitLab before configuring DefectDojo:

1. Navigate to your GitLab profile's Applications page:
   - GitLab.com: `https://gitlab.com/profile/applications`
   - Self-hosted: `https://your-gitlab-host/profile/applications`

2. Create a new application:
   - **Name:** `DefectDojo`
   - **Redirect URI:** `https://your-dojo-host/complete/gitlab/`

3. Note the **Application ID** and **Secret** from the application.

## Configuration

Set the following as environment variables, or without the `DD_` prefix in your `local_settings.py` file (see [Configuration](/get_started/open_source/configuration/)):

{{< highlight python >}}
DD_SOCIAL_AUTH_GITLAB_KEY=(str, 'YOUR_APPLICATION_ID'),
DD_SOCIAL_AUTH_GITLAB_SECRET=(str, 'YOUR_SECRET'),
DD_SOCIAL_AUTH_GITLAB_API_URL=(str, 'https://gitlab.com'),
DD_SOCIAL_AUTH_GITLAB_OAUTH2_ENABLED=True
{{< /highlight >}}

Restart DefectDojo. A **Login with GitLab** button will appear on the login page.

### Auto-importing GitLab projects

To automatically import your GitLab projects as DefectDojo Products, add the following variable:

{{< highlight python >}}
DD_SOCIAL_AUTH_GITLAB_PROJECT_AUTO_IMPORT=True
{{< /highlight >}}

**Note:** Enabling this on an existing instance with a GitLab integration will require users to re-grant the `read_repository` permission.
