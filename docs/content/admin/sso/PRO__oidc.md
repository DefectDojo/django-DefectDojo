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
4. Check **Enable OIDC**.

Submit the form. A **Log In With OIDC** button will appear on the DefectDojo login page.
