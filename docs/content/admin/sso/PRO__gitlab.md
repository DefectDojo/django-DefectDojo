---
title: "GitLab"
description: "Configure GitLab SSO in DefectDojo Pro"
weight: 9
audience: pro
---

DefectDojo Pro supports login via GitLab. Open-Source users should refer to the [Open-Source GitLab guide](/admin/sso/os__gitlab/).

## Prerequisites

Complete the following steps in GitLab before configuring DefectDojo:

1. Navigate to your GitLab profile's Applications page:
   - GitLab.com: `https://gitlab.com/profile/applications`
   - Self-hosted: `https://your-gitlab-host/profile/applications`

2. Create a new application:
   - **Name:** `DefectDojo`
   - **Redirect URI:** `https://your-dojo-instance.cloud.defectdojo.com/complete/gitlab/`

3. Note the **Application ID** and **Secret** from the application.

## Configuration

In DefectDojo, go to **Enterprise Settings > OAuth Settings**, select **GitLab**, and fill in the form:

- **GitLab OAuth Key** — enter your **Application ID**
- **GitLab OAuth Secret** — enter your **Secret**
- **GitLab API URL** — enter the base URL of your GitLab instance, e.g. `https://gitlab.com`

Check **Enable GitLab OAuth** and submit the form. A **Login With GitLab** button will appear on the login page.
