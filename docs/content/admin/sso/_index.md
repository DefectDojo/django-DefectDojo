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
  - "/en/customize_dojo/user_management/configure_sso/"
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
---

Single Sign-On is a **DefectDojo Pro** feature. As of DefectDojo 3.0, the SSO surface — SAML, OIDC, and the bundled OAuth providers — is available only in DefectDojo Pro. Open-source DefectDojo uses local username/password login and the password-reset flow.

If you're running open-source DefectDojo and want SSO, you'll need to switch to [DefectDojo Pro](https://defectdojo.com); the migration is covered in the [3.0 upgrade notes](/releases/os_upgrading/3.0/#sso-providers-are-available-in-defectdojo-pro-only). Existing user accounts and group memberships are preserved on upgrade. For access control on open-source DefectDojo, see the [Authorized Users](/admin/user_management/os__authorized_users/) page.

## How SSO configuration works

Two things are worth understanding before you set up a provider:

- **Where settings live.** Almost every provider is configured in the **Enterprise Settings** UI (SAML, OIDC, the OAuth providers, LDAP, SCIM). Those values are saved in DefectDojo and take effect immediately — no restart. Two providers are the exception: [Remote User (Header) Authentication](/admin/sso/pro__remote_user/) is configured with environment variables only, and on-premise installs may *also* set any provider's boot-time defaults through environment variables. Where both exist, **the Enterprise Settings value wins at runtime** — the environment variable is only the starting default.
- **Configured vs enabled.** Filling in a provider's form does not switch it on. Each provider has its own **Enable** checkbox; the login button (or, for LDAP, the credential check) only appears once the provider is both configured and enabled and the form is saved. [Authorization Connectors](/admin/sso/pro__authorization_connectors/) shows both states on one page.

SSO, LDAP and SCIM are part of the DefectDojo Pro licensed feature set. If the Enterprise Settings pages for these providers are not visible, your subscription does not include them — contact DefectDojo Support.

## Seeing what is configured

**[Authorization Connectors](/admin/sso/pro__authorization_connectors/)** lists every supported provider on one page — which are configured, which are enabled, and what protocol each speaks — and takes you straight to the settings form for any of them. Start there if you want to know the state of this instance rather than set up a specific provider.

## Supported SSO providers (DefectDojo Pro)

Each guide walks through the provider-side setup and the corresponding configuration in DefectDojo. The generic standards come first, then the branded OAuth providers, then the directory-backed methods.

**Standards**

* **[SAML](/admin/sso/pro__saml/)** — SAML 2.0
* **[OIDC (OpenID Connect)](/admin/sso/pro__oidc/)** — any OpenID Connect provider

**OAuth 2.0 providers**

* **[Auth0](/admin/sso/pro__auth0/)**
* **[Azure Active Directory / Microsoft Entra ID](/admin/sso/pro__azure_ad/)**
* **[GitHub Enterprise](/admin/sso/pro__github_enterprise/)**
* **[GitLab](/admin/sso/pro__gitlab/)**
* **[Google](/admin/sso/pro__google/)**
* **[KeyCloak](/admin/sso/pro__keycloak/)**
* **[Okta](/admin/sso/pro__okta/)**

**Directory / proxy**

* **[LDAP](/admin/sso/pro__ldap/)** — sign in against your LDAP or Active Directory
* **[Remote User (Header) Authentication](/admin/sso/pro__remote_user/)** — trust an authenticating reverse proxy (environment-variable configured)

Each provider's page states the exact **callback / redirect URI** to register at your identity provider. You can also read it back from the provider's own settings form using **Validate Config**, which echoes the value DefectDojo expects.

## Provisioning users from your directory (DefectDojo Pro)

The providers above decide who may sign in. **[SCIM Provisioning](/admin/sso/pro__scim/)** keeps the account list itself in step with your directory, so users are created when they join, updated when their details change, and deactivated (along with their API tokens) when they leave.

SSO configuration in DefectDojo Pro can only be performed by a **Superuser**.

**DefectDojo Pro users:** Add the IP addresses of your SAML or SSO services to the Firewall whitelist before setting up SSO. See [Firewall Rules](/get_started/pro/cloud/using-cloud-manager/#changing-your-firewall-settings) for more information.

## The login page itself

How the login page behaves once SSO is in place — disabling username/password login, auto-redirecting to your provider, session length, and just-in-time user creation — is covered on the [Login Settings](/admin/sso/pro__login_settings/) page.

If your SSO integration stops working, you can always return to the standard login form by appending `?force_login_form` to your DefectDojo login URL. Keep at least one Superuser account with a username and password as a break-glass fallback.
