---
title: "OIDC"
description: "Configure OpenID Connect (OIDC) SSO in DefectDojo Pro"
weight: 17
audience: pro
---

DefectDojo Pro supports login via a generic OpenID Connect (OIDC) provider. Open-source DefectDojo does not include SSO — see [Authorized Users](/admin/user_management/os__authorized_users/) for open-source access control.

## Configuration

In DefectDojo, go to **Enterprise Settings > OIDC Settings**.

![image](images/oidc_pro.png)

Fill in the form:

1. **Endpoint** — the base URL of your OIDC provider. Do not include `/.well-known/openid-configuration`.
2. **Client ID** — your OIDC client ID.
3. **Client Secret** — your OIDC client secret.
4. **Username Claim** *(optional)* — the OIDC claim whose value DefectDojo uses as the username when it creates a new user. Leave this blank to use the standard `preferred_username` claim.
5. Check **Enable OIDC**.

Submit the form. A **Log In With OIDC** button will appear on the DefectDojo login page.

## Choosing the username claim

DefectDojo reads the **Username Claim** when it **provisions a new user** through OIDC — the value of that claim becomes the user's DefectDojo username. Leave the field blank to use the standard `preferred_username` claim.

This setting affects **new** usernames only. When a returning user logs in, DefectDojo matches them to their existing account by the provider's subject identifier and then by email address — not by this claim — so changing the Username Claim does not change how existing users are matched.

Override the default when:

- **Your provider doesn't emit `preferred_username`,** or emits it empty. Point DefectDojo at a claim your IdP actually populates.
- **You want usernames in a specific form** — for example a corporate login name or a specific email claim. Set the Username Claim to the claim that carries the value you want new DefectDojo usernames to take.

If the configured claim is missing from a user's token, DefectDojo falls back to the user's **email address** as the username. If there is no email either, the login fails with an error rather than creating a blank username — so make sure the claim you choose (or the email claim) is always present for every user who logs in via OIDC.

> **Note:** The Username Claim applies to the generic **OIDC** provider only. The bundled OAuth providers (Google, Azure AD, Okta, and so on) determine usernames on their own and are not affected by this setting.
