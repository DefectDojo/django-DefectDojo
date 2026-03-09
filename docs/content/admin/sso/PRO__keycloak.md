---
title: "KeyCloak"
description: "Configure KeyCloak SSO in DefectDojo Pro"
weight: 13
audience: pro
---

DefectDojo Pro supports login via KeyCloak. Open-Source users should refer to the [Open-Source KeyCloak guide](../OS__keycloak/).

This guide assumes you already have a KeyCloak Realm configured. If not, see the [KeyCloak documentation](https://wjw465150.gitbooks.io/keycloak-documentation/content/server_admin/topics/realms/create.html).

## Prerequisites

Complete the following steps in your KeyCloak realm before configuring DefectDojo:

1. Add a new client with type `openid-connect`. Note the client ID.

2. In the client settings:
   - Set **Access Type** to `confidential`
   - Under **Valid Redirect URIs**, add your DefectDojo URL, e.g. `https://yourorganization.cloud.defectdojo.com` or `https://your-dojo-host/*`
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

In DefectDojo, go to **Enterprise Settings > OAuth Settings**, select **KeyCloak**, and fill in the form:

- **KeyCloak OAuth Key** — enter your client name (from step 1)
- **KeyCloak OAuth Secret** — enter your client credentials secret (from step 5)
- **KeyCloak Public Key** — enter the Public Key from your realm settings (from step 6)
- **KeyCloak Resource** — enter the Authorization Endpoint URL (from step 7)
- **KeyCloak Group Limiter** — enter the Token Endpoint URL (from step 7)
- **KeyCloak OAuth Login Button Text** — choose the text for the DefectDojo login button

Check **Enable KeyCloak OAuth** and submit the form. A login button will appear on the login page with the text you configured.
