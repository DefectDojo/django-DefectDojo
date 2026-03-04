---
title: "GitHub Enterprise"
description: "Configure GitHub Enterprise SSO in DefectDojo Pro"
weight: 7
audience: pro
---

DefectDojo Pro supports login via GitHub Enterprise. Open-Source users should refer to the [Open-Source GitHub Enterprise guide](/admin/sso/os__github_enterprise/).

## Prerequisites

Complete the following steps in GitHub Enterprise before configuring DefectDojo:

1. [Create a new OAuth App](https://docs.github.com/en/enterprise-server/developers/apps/building-oauth-apps/creating-an-oauth-app) in your GitHub Enterprise Server.

2. Choose a name for the application, e.g. `DefectDojo`.

3. Set the **Redirect URI**:
   `https://your-instance.cloud.defectdojo.com/complete/github-enterprise/`

4. Note the **Client ID** and **Client Secret** from the app.

## Configuration

In DefectDojo, go to **Enterprise Settings > OAuth Settings**, select **GitHub Enterprise**, and fill in the form:

- **GitHub Enterprise OAuth Key** — enter your **Client ID**
- **GitHub Enterprise OAuth Secret** — enter your **Client Secret**
- **GitHub Enterprise URL** — enter your organization's GitHub URL, e.g. `https://github.yourcompany.com/`
- **GitHub Enterprise API URL** — enter your organization's GitHub API URL, e.g. `https://github.yourcompany.com/api/v3/`

Check **Enable GitHub Enterprise OAuth** and submit the form. A **Login With GitHub** button will appear on the login page.
