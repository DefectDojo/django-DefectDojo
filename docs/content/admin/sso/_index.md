---
title: "Single Sign-On"
description: "DefectDojo Pro supports SAML and a range of OAuth providers for Single Sign-On"
summary: ""
date: 2023-09-07T16:06:50+02:00
lastmod: 2026-04-30T00:00:00+00:00
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
pro-feature: true
aliases:
  - /admin/user_management/configure_sso/
  - /admin/sso/os__saml/
  - /admin/sso/os__auth0/
  - /admin/sso/os__azure_ad/
  - /admin/sso/os__github_enterprise/
  - /admin/sso/os__gitlab/
  - /admin/sso/os__google/
  - /admin/sso/os__keycloak/
  - /admin/sso/os__oidc/
  - /admin/sso/os__okta/
  - /admin/sso/os__remote_user/
---

Single Sign-On is a **DefectDojo Pro** feature. As of DefectDojo 2.59, the SSO surface — SAML, OIDC, and the bundled OAuth providers — is available only in DefectDojo Pro. Open-source DefectDojo uses local username/password login and the password-reset flow.

If you're running open-source DefectDojo and want SSO, you'll need to switch to [DefectDojo Pro](https://defectdojo.com); the migration is covered in the [2.59 upgrade notes](/releases/os_upgrading/2.59/#sso-providers-are-available-in-defectdojo-pro-only). Existing user accounts and group memberships are preserved on upgrade. For access control on open-source DefectDojo, see the [Authorized Users](/admin/user_management/os__authorized_users/) page.

## Supported SSO providers (DefectDojo Pro)

DefectDojo Pro supports SAML and the following OAuth providers. Each guide walks through the provider-side setup and the corresponding configuration in the Pro **Enterprise Settings** UI.

* **[Auth0](/admin/sso/pro__auth0/)**
* **[Azure Active Directory](/admin/sso/pro__azure_ad/)**
* **[GitHub Enterprise](/admin/sso/pro__github_enterprise/)**
* **[GitLab](/admin/sso/pro__gitlab/)**
* **[Google](/admin/sso/pro__google/)**
* **[KeyCloak](/admin/sso/pro__keycloak/)**
* **[Okta](/admin/sso/pro__okta/)**
* **[OIDC (OpenID Connect)](/admin/sso/pro__oidc/)**
* **[SAML](/admin/sso/pro__saml/)**

SSO configuration in DefectDojo Pro can only be performed by a **Superuser**.

**DefectDojo Pro users:** Add the IP addresses of your SAML or SSO services to the Firewall whitelist before setting up SSO. See [Firewall Rules](/get_started/pro/cloud/using-cloud-manager/#changing-your-firewall-settings) for more information.

## Disabling Username / Password login

Once SSO is configured in DefectDojo Pro, you may want to disable the traditional username/password login form. Uncheck **Allow Login via Username and Password** under **Enterprise Settings > Login Settings**.

![image](images/pro_login_settings.png)

### Login fallback

If your SSO integration stops working, you can always return to the standard login form by appending the following to your DefectDojo URL:

`/login?force_login_form`

We recommend keeping at least one admin account with a username and password configured as a fallback.
