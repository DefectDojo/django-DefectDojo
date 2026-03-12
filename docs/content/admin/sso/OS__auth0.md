---
title: "Auth0"
description: "Configure Auth0 SSO in Open-Source DefectDojo"
weight: 4
audience: opensource
---

Open-Source DefectDojo supports login via Auth0. DefectDojo Pro users should refer to the [Pro Auth0 guide](../PRO__auth0/).

## Prerequisites

Complete the following steps in your Auth0 dashboard before configuring DefectDojo:

1. Create a new application: **Applications > Create Application > Single Page Web Application**.

2. Configure the application:
   - **Name:** `DefectDojo`
   - **Allowed Callback URLs:** `https://your-instance.cloud.defectdojo.com/complete/auth0/`

3. Note the following values — you will need them in DefectDojo:
   - **Domain**
   - **Client ID**
   - **Client Secret**

## Configuration

Set the following as environment variables, or without the `DD_` prefix in your `local_settings.py` file (see [Configuration](/get_started/open_source/configuration/)):

{{< highlight python >}}
DD_SOCIAL_AUTH_AUTH0_OAUTH2_ENABLED=True
DD_SOCIAL_AUTH_AUTH0_KEY=(str, 'YOUR_CLIENT_ID'),
DD_SOCIAL_AUTH_AUTH0_SECRET=(str, 'YOUR_CLIENT_SECRET'),
DD_SOCIAL_AUTH_AUTH0_DOMAIN=(str, 'YOUR_AUTH0_DOMAIN'),
{{< /highlight >}}

Restart DefectDojo. A **Login with Auth0** button will appear on the login page.
