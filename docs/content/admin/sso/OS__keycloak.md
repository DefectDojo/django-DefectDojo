---
title: "KeyCloak"
description: "Configure KeyCloak SSO in Open-Source DefectDojo"
weight: 14
audience: opensource
---

Open-Source DefectDojo supports login via KeyCloak. DefectDojo Pro users should refer to the [Pro KeyCloak guide](/admin/sso/pro__keycloak/).

This guide assumes you already have a KeyCloak Realm configured. If not, see the [KeyCloak documentation](https://wjw465150.gitbooks.io/keycloak-documentation/content/server_admin/topics/realms/create.html).

## Prerequisites

Complete the following steps in your KeyCloak realm before configuring DefectDojo:

1. Add a new client with type `openid-connect`. Note the client ID.

2. In the client settings:
   - Set **Access Type** to `confidential`
   - Under **Valid Redirect URIs**, add your DefectDojo URL, e.g. `https://your-dojo-host/*`
   - Under **Web Origins**, add the same URL (or `+`)
   - Under **Fine Grained OpenID Connect Configuration**:
     - Set **User Info Signed Response Algorithm** to `RS256`
     - Set **Request Object Signature Algorithm** to `RS256`
   - Save the settings.

3. Under **Scope**, set **Full Scope Allowed** to `off`.

4. Under **Mappers**, add a custom mapper:
   - **Name:** `aud`
   - **Mapper Type:** `audience`
   - **Included Audience:** select your client ID
   - **Add ID to Token:** `off`
   - **Add Access to Token:** `on`

5. Under **Credentials**, copy the **Secret**.

6. In **Realm Settings > Keys**, copy the **Public Key** (signing key).

7. In **Realm Settings > General > Endpoints**, open the OpenID endpoint configuration and copy the **Authorization** and **Token** endpoint URLs.

## Configuration

Set the following as environment variables, or without the `DD_` prefix in your `local_settings.py` file (see [Configuration](/get_started/open_source/configuration/)):

{{< highlight python >}}
DD_SESSION_COOKIE_SECURE=True,
DD_CSRF_COOKIE_SECURE=True,
DD_SECURE_SSL_REDIRECT=True,
DD_SOCIAL_AUTH_KEYCLOAK_OAUTH2_ENABLED=True,
DD_SOCIAL_AUTH_KEYCLOAK_PUBLIC_KEY=(str, 'YOUR_REALM_PUBLIC_KEY'),
DD_SOCIAL_AUTH_KEYCLOAK_KEY=(str, 'YOUR_CLIENT_ID'),
DD_SOCIAL_AUTH_KEYCLOAK_SECRET=(str, 'YOUR_CLIENT_SECRET'),
DD_SOCIAL_AUTH_KEYCLOAK_AUTHORIZATION_URL=(str, 'YOUR_AUTHORIZATION_ENDPOINT'),
DD_SOCIAL_AUTH_KEYCLOAK_ACCESS_TOKEN_URL=(str, 'YOUR_TOKEN_ENDPOINT')
{{< /highlight >}}

For Helm deployments, add the following to the `extraConfig` section:

```yaml
DD_SESSION_COOKIE_SECURE: 'True'
DD_CSRF_COOKIE_SECURE: 'True'
DD_SECURE_SSL_REDIRECT: 'True'
DD_SOCIAL_AUTH_KEYCLOAK_OAUTH2_ENABLED: 'True'
DD_SOCIAL_AUTH_KEYCLOAK_PUBLIC_KEY: '<your realm public key>'
DD_SOCIAL_AUTH_KEYCLOAK_KEY: '<your client id>'
DD_SOCIAL_AUTH_KEYCLOAK_SECRET: '<your keycloak client credentials secret>'
DD_SOCIAL_AUTH_KEYCLOAK_AUTHORIZATION_URL: '<your authorization endpoint>'
DD_SOCIAL_AUTH_KEYCLOAK_ACCESS_TOKEN_URL: '<your token endpoint>'
```

Optionally, set `DD_SOCIAL_AUTH_KEYCLOAK_LOGIN_BUTTON_TEXT` to customize the login button text.

Restart DefectDojo. A login button will appear on the login page with your configured text.
