---
title: "OIDC"
description: "Configure OpenID Connect (OIDC) SSO in DefectDojo Pro"
weight: 17
audience: pro
---

DefectDojo Pro supports login via a generic OpenID Connect (OIDC) provider. Open-Source users should refer to the [Open-Source OIDC guide](../OS__oidc/).

## Configuration

In DefectDojo, go to **Enterprise Settings > OIDC Settings**.

![image](images/oidc_pro.png)

Fill in the form:

1. **Endpoint** — the base URL of your OIDC provider. Do not include `/.well-known/openid-configuration`.
2. **Client ID** — your OIDC client ID.
3. **Client Secret** — your OIDC client secret.
4. Check **Enable OIDC**.

Submit the form. A **Log In With OIDC** button will appear on the DefectDojo login page.
