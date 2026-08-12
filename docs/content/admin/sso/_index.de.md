---
title: Single Sign-On
description: DefectDojo Pro unterstützt SAML und eine Reihe von OAuth-Anbietern für
  Single Sign-On
summary: ''
date: 2023-09-07 16:06:50+02:00
lastmod: 2026-04-30 00:00:00+00:00
draft: false
weight: 8
collapsed: true
chapter: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
exclude_search: true
pro-feature: true
aliases:
- /de/admin/user_management/configure_sso/
- /de/admin/sso/os__saml/
- /de/admin/sso/os__auth0/
- /de/admin/sso/os__azure_ad/
- /de/admin/sso/os__github_enterprise/
- /de/admin/sso/os__gitlab/
- /de/admin/sso/os__google/
- /de/admin/sso/os__keycloak/
- /de/admin/sso/os__oidc/
- /de/admin/sso/os__okta/
- /de/admin/sso/os__remote_user/
---

Single Sign-On ist eine Funktion von **DefectDojo Pro**. Seit DefectDojo 3.0 ist der SSO-Funktionsumfang – SAML, OIDC und die mitgelieferten OAuth-Provider – nur in DefectDojo Pro verfügbar. Open-Source-DefectDojo verwendet die lokale Benutzername/Passwort-Anmeldung und den Passwort-Reset-Ablauf.

Wenn Sie Open-Source-DefectDojo betreiben und SSO nutzen möchten, müssen Sie zu [DefectDojo Pro](https://defectdojo.com) wechseln; die Migration wird in den [3.0-Upgrade-Hinweisen](/releases/os_upgrading/3.0/#sso-providers-are-available-in-defectdojo-pro-only) beschrieben. Bestehende Benutzerkonten und Gruppenmitgliedschaften bleiben beim Upgrade erhalten. Informationen zur Zugriffskontrolle in Open-Source-DefectDojo finden Sie auf der Seite [Autorisierte Benutzer](/admin/user_management/os__authorized_users/).

## Anzeigen der aktuellen Konfiguration

**[Authorization Connectors](/admin/sso/pro__authorization_connectors/)** listet alle unterstützten Provider auf einer Seite auf – welche konfiguriert sind, welche aktiviert sind und welches Protokoll jeder verwendet – und führt Sie direkt zum Einstellungsformular für jeden von ihnen. Beginnen Sie dort, wenn Sie den Status dieser Instanz kennen möchten, statt einen bestimmten Provider einzurichten.

## Unterstützte SSO-Provider (DefectDojo Pro)

DefectDojo Pro unterstützt SAML und die folgenden OAuth-Provider. Jede Anleitung führt durch die Einrichtung auf Provider-Seite und die entsprechende Konfiguration in der Pro-Benutzeroberfläche **Enterprise Settings**.

* **[Auth0](/admin/sso/pro__auth0/)**
* **[Azure Active Directory](/admin/sso/pro__azure_ad/)**
* **[GitHub Enterprise](/admin/sso/pro__github_enterprise/)**
* **[GitLab](/admin/sso/pro__gitlab/)**
* **[Google](/admin/sso/pro__google/)**
* **[KeyCloak](/admin/sso/pro__keycloak/)**
* **[Okta](/admin/sso/pro__okta/)**
* **[OIDC (OpenID Connect)](/admin/sso/pro__oidc/)**
* **[SAML](/admin/sso/pro__saml/)**
* **[LDAP](/admin/sso/pro__ldap/)**

## Bereitstellung von Benutzern aus Ihrem Verzeichnis (DefectDojo Pro)

Die oben genannten Provider entscheiden, wer sich anmelden darf. **[SCIM Provisioning](/admin/sso/pro__scim/)** hält die Kontoliste selbst mit Ihrem Verzeichnis synchron, sodass Benutzer bei ihrem Eintritt erstellt, bei Änderungen ihrer Daten aktualisiert und beim Austritt (zusammen mit ihren API-Tokens) deaktiviert werden.

Die SSO-Konfiguration in DefectDojo Pro kann nur von einem **Superuser** vorgenommen werden.

**DefectDojo-Pro-Benutzer:** Fügen Sie die IP-Adressen Ihrer SAML- oder SSO-Dienste vor der Einrichtung von SSO zur Firewall-Whitelist hinzu. Weitere Informationen finden Sie unter [Firewall-Regeln](/get_started/pro/cloud/using-cloud-manager/#changing-your-firewall-settings).

## Deaktivieren der Benutzername-/Passwort-Anmeldung

Sobald SSO in DefectDojo Pro konfiguriert ist, möchten Sie möglicherweise das klassische Anmeldeformular mit Benutzername/Passwort deaktivieren. Deaktivieren Sie **Allow Login via Username and Password** unter **Enterprise Settings > Login Settings**.

![image](images/pro_login_settings.png)

### Anmelde-Fallback

Wenn Ihre SSO-Integration nicht mehr funktioniert, können Sie jederzeit zum Standard-Anmeldeformular zurückkehren, indem Sie Folgendes an Ihre DefectDojo-URL anhängen:

`/login?force_login_form`

Wir empfehlen, mindestens ein Admin-Konto mit konfiguriertem Benutzernamen und Passwort als Fallback beizubehalten.
