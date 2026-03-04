---
title: "OIDC"
description: "Configure OpenID Connect (OIDC) SSO in Open-Source DefectDojo"
weight: 18
audience: opensource
---

Open-Source DefectDojo supports login via a generic OpenID Connect (OIDC) provider. DefectDojo Pro users should refer to the [Pro OIDC guide](/admin/sso/pro__oidc/).

## Configuration

Set the following required variables as environment variables, or without the `DD_` prefix in your `local_settings.py` file (see [Configuration](/get_started/open_source/configuration/)):

{{< highlight python >}}
DD_SOCIAL_AUTH_OIDC_AUTH_ENABLED=True,
DD_SOCIAL_AUTH_OIDC_OIDC_ENDPOINT=(str, 'https://your-oidc-provider.com'),
DD_SOCIAL_AUTH_OIDC_KEY=(str, 'YOUR_CLIENT_ID'),
DD_SOCIAL_AUTH_OIDC_SECRET=(str, 'YOUR_CLIENT_SECRET')
{{< /highlight >}}

The remaining OIDC configuration is auto-detected by fetching:
`<DD_SOCIAL_AUTH_OIDC_OIDC_ENDPOINT>/.well-known/openid-configuration`

Restart DefectDojo. A **Log In With OIDC** button will appear on the login page.

## Optional Variables

{{< highlight python >}}
DD_SOCIAL_AUTH_OIDC_ID_KEY=(str, ''),                          # Key associated with OIDC user IDs
DD_SOCIAL_AUTH_OIDC_USERNAME_KEY=(str, ''),                    # Key associated with OIDC usernames
DD_SOCIAL_AUTH_CREATE_USER_MAPPING=(str, 'username'),          # Can also be 'email' or 'fullname'
DD_SOCIAL_AUTH_OIDC_WHITELISTED_DOMAINS=(list, ['']),          # Domains allowed for login
DD_SOCIAL_AUTH_OIDC_JWT_ALGORITHMS=(list, ['RS256', 'HS256']),
DD_SOCIAL_AUTH_OIDC_ID_TOKEN_ISSUER=(str, ''),
DD_SOCIAL_AUTH_OIDC_ACCESS_TOKEN_URL=(str, ''),
DD_SOCIAL_AUTH_OIDC_AUTHORIZATION_URL=(str, ''),
DD_SOCIAL_AUTH_OIDC_USERINFO_URL=(str, ''),
DD_SOCIAL_AUTH_OIDC_JWKS_URI=(str, ''),
DD_SOCIAL_AUTH_OIDC_LOGIN_BUTTON_TEXT=(str, 'Login with OIDC'),
{{< /highlight >}}
