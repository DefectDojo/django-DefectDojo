---
title: "Single Sign-On"
description: "Set Up User Permissions, SSO and Groups"
summary: ""
date: 2023-09-07T16:06:50+02:00
lastmod: 2023-09-07T16:06:50+02:00
draft: false
weight: 8
collapsed: true
chapter: true
seo:
  title: ""
  description: ""
  canonical: ""
  robots: ""
exclude_search: true
aliases:
  - /admin/user_management/configure_sso/
---

Users can connect to DefectDojo with a Username and Password, but you can also allow users to authenticate via Single Sign-On (SSO). DefectDojo supports SAML and a range of OAuth providers:

* **[Auth0](./PRO__auth0/)**
* **[Azure Active Directory](./PRO__azure_ad/)**
* **[GitHub Enterprise](./PRO__github_enterprise/)**
* **[GitLab](./PRO__gitlab/)**
* **[Google](./PRO__google/)**
* **[KeyCloak](./PRO__keycloak/)**
* **[Okta](./PRO__okta/)**
* **[OIDC (OpenID Connect)](./PRO__oidc/)**
* **[SAML](./PRO__saml/)**

SSO configuration can only be performed by a **Superuser**.

**DefectDojo Pro users:** Add the IP addresses of your SAML or SSO services to the Firewall whitelist before setting up SSO. See [Firewall Rules](/get_started/pro/cloud/using-cloud-manager/#changing-your-firewall-settings) for more information.

## Disabling Username / Password Login

Once SSO is configured, you may want to disable traditional username/password login.

**DefectDojo Pro** users can uncheck **Allow Login via Username and Password** under **Enterprise Settings > Login Settings**.

![image](images/pro_login_settings.png)

**Open-Source** users can set the following environment variables in Docker:

```yaml
DD_SOCIAL_LOGIN_AUTO_REDIRECT: "true"
DD_SOCIAL_AUTH_SHOW_LOGIN_FORM: "false"
```

### Login Fallback

If your SSO integration stops working, you can always return to the standard login form by appending the following to your DefectDojo URL:

`/login?force_login_form`

We recommend keeping at least one admin account with a username and password configured as a fallback.
