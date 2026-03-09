---
title: "Okta"
description: "Configure Okta SSO in Open-Source DefectDojo"
weight: 16
audience: opensource
---

Open-Source DefectDojo supports login via Okta. DefectDojo Pro users should refer to the [Pro Okta guide](../PRO__okta/).

## Prerequisites

Complete the following steps in Okta before configuring DefectDojo:

1. Sign in or create an account at [Okta](https://www.okta.com/developer/signup/).

2. Go to **Applications** and click **Add Application**, then select **Web Applications**.

3. Under **Login Redirect URLs**, add:
   `https://your-dojo-host/complete/okta-oauth2/`
   Also check the **Implicit** box.

4. Click **Done**.

5. From the **Dashboard**, note the **Org-URL**.

6. Open the application and note the **Client ID** and **Client Secret**.

## Configuration

Set the following as environment variables, or without the `DD_` prefix in your `local_settings.py` file (see [Configuration](/get_started/open_source/configuration/)):

{{< highlight python >}}
DD_SOCIAL_AUTH_OKTA_OAUTH2_ENABLED=True,
DD_SOCIAL_AUTH_OKTA_OAUTH2_KEY=(str, 'YOUR_CLIENT_ID'),
DD_SOCIAL_AUTH_OKTA_OAUTH2_SECRET=(str, 'YOUR_CLIENT_SECRET'),
DD_SOCIAL_AUTH_OKTA_OAUTH2_API_URL=(str, 'https://your-org-url/oauth2'),
{{< /highlight >}}

Restart DefectDojo. A **Login With Okta** button will appear on the login page.

### Redirect URI shows http instead of https

If you see the error *The 'redirect_uri' parameter must be an absolute URI that is whitelisted in the client app settings* and the `redirect_uri` starts with `http://` instead of `https://`, add the following:

- **Docker Compose:** `DD_SOCIAL_AUTH_REDIRECT_IS_HTTPS=True`
- **local_settings.py:** `SOCIAL_AUTH_REDIRECT_IS_HTTPS=True`
