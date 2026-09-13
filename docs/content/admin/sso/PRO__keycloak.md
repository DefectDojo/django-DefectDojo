---
title: "KeyCloak"
description: "Configure KeyCloak SSO in DefectDojo Pro"
weight: 100
audience: pro
---

DefectDojo Pro supports login via KeyCloak over OAuth 2.0. Open-source DefectDojo does not include SSO — see [Authorized Users](/admin/user_management/os__authorized_users/) for open-source access control.

This guide assumes you already have a KeyCloak Realm configured. If not, see the [KeyCloak documentation](https://www.keycloak.org/docs/latest/server_admin/#configuring-realms).

## Callback URL

KeyCloak needs the exact redirect URI DefectDojo listens on after a user authenticates. It is your DefectDojo base URL followed by `/complete/keycloak/`:

```
https://<your-instance>.cloud.defectdojo.com/complete/keycloak/
```

On-premise, replace the host with your own DefectDojo base URL, keeping the `/complete/keycloak/` path. Add this value under the client's **Valid Redirect URIs**. A wildcard such as `https://<your-host>/*` also covers it, but registering the exact path is safer.

## Prerequisites

Complete the following steps in your KeyCloak realm before configuring DefectDojo:

1. Add a new client with type `openid-connect`. Note the client ID.

2. In the client settings:
   - Set **Access Type** to `confidential`.
   - Under **Valid Redirect URIs**, add the [Callback URL](#callback-url) above.
   - Under **Web Origins**, add your DefectDojo base URL (or `+`).
   - Under **Fine Grained OpenID Connect Configuration**:
     - Set **User Info Signed Response Algorithm** to `RS256`.
     - Set **Request Object Signature Algorithm** to `RS256`.
   - Save the settings.

3. Under **Scope**, set **Full Scope Allowed** to `off`.

4. Under **Mappers**, add a custom mapper:
   - **Name:** `aud`
   - **Mapper Type:** `audience`
   - **Included Audience:** select your client ID
   - **Add ID to Token:** `off`
   - **Add Access to Token:** `on`

5. Under **Credentials**, copy the **Secret**.

6. In **Realm Settings > Keys**, copy the **Public Key** (the RS256 signing key).

7. In **Realm Settings > General > Endpoints**, open the OpenID endpoint configuration and copy the **authorization_endpoint** and **token_endpoint** URLs.

## Configuration

In DefectDojo, go to **Enterprise Settings > OAuth Settings**, select **KeyCloak**, and fill in the form:

- **KeyCloak OAuth Key** — enter your client ID (from step 1).
- **KeyCloak OAuth Secret** — enter the client secret (from step 5).
- **KeyCloak Public Key** — enter the realm signing key (from step 6). DefectDojo validates the ID-token signature with this key; without it, every login fails.
- **KeyCloak Authorization URL** — enter the `authorization_endpoint` (from step 7).
- **KeyCloak Access Token URL** — enter the `token_endpoint` (from step 7).
- **KeyCloak OAuth Login Button Text** — choose the text for the DefectDojo login button.

Check **Enable KeyCloak OAuth** and submit the form. A login button with your configured text will appear on the login page.

Use **Validate Config** at any point to check the settings without saving them. It confirms the settings are complete, checks that the authorization and token endpoints are reachable, verifies a realm public key is present, and echoes the exact **redirect URI** to register at KeyCloak.

## First login and default access

New users are provisioned automatically on first login (when **Create User on Successful Login** is enabled under **Login Settings**), and existing users are matched by username. A newly provisioned user who is not placed in any group lands on DefectDojo with **no permissions**. To give every new SSO user a baseline, set a **Default group** and **Default group role** on the System Settings page — see [Default access for SSO-provisioned users](/admin/sso/pro__saml/#default-access-for-sso-provisioned-users), which applies to every social-auth provider including KeyCloak.

KeyCloak over OAuth does not synchronize realm groups into DefectDojo groups. If you need directory-driven group membership from KeyCloak, use the generic [OIDC](/admin/sso/pro__oidc/) provider instead — it supports OIDC group mapping and a KeyCloak *Group Membership* mapper — or [SAML](/admin/sso/pro__saml/).

## Troubleshooting

**Every login fails with a signature or token error.** The **KeyCloak Public Key** is missing or is not the realm's RS256 signing key. Recopy it from **Realm Settings > Keys** and confirm the client's signature algorithms are set to `RS256` (step 2).

**Login fails immediately after the KeyCloak prompt.** A redirect-URI mismatch. Confirm the client's **Valid Redirect URIs** include the exact [Callback URL](#callback-url).

**Authorization or token endpoint unreachable in Validate Config.** The endpoint URLs are wrong or the realm name in them is incorrect. Recopy both from the realm's OpenID endpoint configuration (step 7).

**Start with Diagnostics.** Rejected sign-ins are recorded under **Connect > Diagnostics** with the reason each was refused. See [Authorization Connectors](/admin/sso/pro__authorization_connectors/) for the difference between what is configured and why a sign-in failed.
