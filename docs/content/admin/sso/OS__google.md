---
title: "Google Auth"
description: "Configure Google OAuth in Open-Source DefectDojo"
weight: 12
audience: opensource
---

Open-Source DefectDojo supports login via Google accounts. New users are created automatically on first login if they don't already exist. Existing DefectDojo users are matched to Google accounts by username (the portion before the `@` in their Google email). DefectDojo Pro users should refer to the [Pro Google guide](../PRO__google/).

## Prerequisites

Complete the following steps in the Google Cloud Console before configuring DefectDojo:

1. Sign in to the [Google Developers Console](https://console.developers.google.com).

2. Go to **Credentials > Create Credentials > OAuth Client ID**.

3. Select **Web Application** and give it a descriptive name (e.g. `DefectDojo`).

4. Under **Authorized Redirect URIs**, add:
   `https://your-dojo-host/complete/google-oauth2/`

5. Note the **Client ID** and **Client Secret Key**.

## Configuration

Set the following as environment variables, or without the `DD_` prefix in your `local_settings.py` file (see [Configuration](/get_started/open_source/configuration/)):

{{< highlight python >}}
DD_SOCIAL_AUTH_GOOGLE_OAUTH2_ENABLED=True,
DD_SOCIAL_AUTH_GOOGLE_OAUTH2_KEY=(str, 'YOUR_CLIENT_ID'),
DD_SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET=(str, 'YOUR_CLIENT_SECRET'),
{{< /highlight >}}

You must also authorize which users can log in. You can whitelist by domain:

{{< highlight python >}}
DD_SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_DOMAINS=['example.com', 'example.org']
{{< /highlight >}}

Or as an environment variable (comma-separated):

{{< highlight python >}}
DD_SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_DOMAINS=example.com,example.org
{{< /highlight >}}

Alternatively, whitelist specific email addresses:

{{< highlight python >}}
DD_SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_EMAILS=['user@example.com']
{{< /highlight >}}

Or as an environment variable:

{{< highlight python >}}
DD_SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_EMAILS=user@example.com,user2@example.com
{{< /highlight >}}

Restart DefectDojo. A **Login With Google** button will appear on the login page.
