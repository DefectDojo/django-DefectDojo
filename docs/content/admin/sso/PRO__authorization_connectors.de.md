---
title: Authorization Connectors
description: 'Sehen Sie alle Identitätsanbieter auf einer Seite: welche konfiguriert
  sind, welche aktiviert sind und welches Protokoll jeder verwendet'
weight: 1
audience: pro
---

Authorization Connectors ist eine einzige Seite, die jeden von DefectDojo Pro unterstützten Identitätsanbieter auflistet, mit dem Status, in dem sich jeder befindet, und dem Protokoll, das er verwendet. Bevor es diese Seite gab, hatte jeder Anbieter sein eigenes Einstellungsformular, und es gab keine Möglichkeit zu beantworten, „was ist auf dieser Instanz eingerichtet?", ohne alle einzeln zu öffnen.

Authorization Connectors ist eine **DefectDojo Pro**-Funktion. Sie finden sie unter **Connect > Authorization**. Nur ein **Superuser** kann die Konfiguration von Identitätsanbietern einsehen oder ändern.

![Authorization Connectors](images/authorization_connectors.png)

## Wie die Seite aufgebaut ist

Die Anbieter sind in zwei Abschnitte unterteilt, und jeder Abschnitt ist alphabetisch sortiert mit einer Anzahl neben seiner Überschrift:

* **Configured Providers** — Anbieter, die auf dieser Instanz eingerichtet wurden, unabhängig davon, ob sie derzeit aktiviert sind.
* **Available Providers** — Anbieter, die unterstützt werden, aber noch nicht eingerichtet sind.

Die Unterteilung erfolgt bewusst nach *konfiguriert*, nicht nach *aktiviert*. Ein Anbieter, der eingerichtet und anschließend deaktiviert wurde, bleibt unter Configured Providers, da genau dort die Person, die ihn eingerichtet hat, danach suchen wird. Sein Status wird stattdessen auf der Kachel angezeigt.

Jede Kachel zeigt:

| | |
| --- | --- |
| **Logo und Name** | Der Anbieter, benannt ohne sein Protokoll |
| **Protokoll-Tag** | `SAML 2.0`, `OAuth 2.0`, `OpenID Connect` oder `LDAP` |
| **Status-Tag** | `Enabled`, `Disabled` oder `Not configured` |
| **`BETA`-Tag** | Vorhanden bei Anbietern, die sich noch in der Beta-Phase befinden |
| **Aktion** | **Manage Configuration** für einen konfigurierten Anbieter, **Configure** für einen verfügbaren |

Beide Abschnitte verfügen über ein Suchfeld, das nach Anbietername und Protokoll sucht, sodass eine Suche nach `oauth` die Seite auf die OAuth-Anbieter eingrenzt.

![Available providers](images/authorization_available.png)

## Eine Konfiguration pro Anbieter

Die Einstellungen eines Identitätsanbieters bestehen aus einem einzigen Satz von Werten pro Anbieter und Instanz — eine Okta-Anwendung, ein SAML-Identitätsanbieter, ein LDAP-Verzeichnis. Die Kacheln weisen darauf hin, und es gibt kein „weiteren hinzufügen": Um zu ändern, wie ein Anbieter eingerichtet ist, bearbeiten Sie die bereits vorhandene Konfiguration.

Dadurch unterscheidet sich Authorization Connectors von den [Connector-Galerien](/connectors/upstream/about/), bei denen ein Tool viele Konfigurationen nebeneinander haben kann.

## Die drei Status und ihre Bedeutung

| Status | Bedeutung | Nächster Schritt |
| --- | --- | --- |
| **Enabled** | Konfiguriert und akzeptiert Anmeldungen | Nichts |
| **Disabled** | Konfiguriert, aber deaktiviert — die Schaltfläche erscheint nicht auf der Anmeldeseite | Über die Konfiguration wieder aktivieren, wenn Sie sie zurückhaben möchten |
| **Not configured** | Unterstützt, aber noch nichts ausgefüllt | **Configure**, um sie einzurichten |

Die Auswahl eines Anbieters öffnet direkt dessen eigenes Einstellungsformular. Es gibt keine zwischengeschaltete Anbieterauswahl.

## Unterstützte Anbieter

| Anbieter | Protokoll | Einrichtungsanleitung |
| --- | --- | --- |
| Auth0 | OAuth 2.0 | [Auth0](/admin/sso/pro__auth0/) |
| GitHub Enterprise | OAuth 2.0 | [GitHub Enterprise](/admin/sso/pro__github_enterprise/) |
| GitLab | OAuth 2.0 | [GitLab](/admin/sso/pro__gitlab/) |
| Google | OAuth 2.0 | [Google](/admin/sso/pro__google/) |
| Keycloak | OAuth 2.0 | [KeyCloak](/admin/sso/pro__keycloak/) |
| LDAP | LDAP | [LDAP](/admin/sso/pro__ldap/) |
| Microsoft Entra ID | OAuth 2.0 | [Azure Active Directory](/admin/sso/pro__azure_ad/) |
| Okta | OAuth 2.0 | [Okta](/admin/sso/pro__okta/) |
| OpenID Connect | OpenID Connect | [OIDC](/admin/sso/pro__oidc/) |
| SAML | SAML 2.0 | [SAML](/admin/sso/pro__saml/) |

Die Seite zeigt an, welchen Konfigurations*status* ein Anbieter hat. Sie gibt niemals die Geheimnisse der Konfiguration zurück — Client Secrets, Bind-Passwörter und Zertifikate sind nicht Teil der Daten hinter dieser Seite und lassen sich daraus nicht wieder auslesen.

## Wenn sich ein Anbieter nicht verbinden lässt

Authorization Connectors zeigt Ihnen, was konfiguriert ist; es zeigt Ihnen keine fehlgeschlagenen Anmeldungen. Diese werden in [Diagnostics](/admin/diagnostics/pro__diagnostics/) protokolliert, wo SSO, SAML und LDAP jeweils ihre eigenen Versuche mit dem Grund der Ablehnung melden — eine ungültige Assertion-Signatur, ein abgelehnter Bind, ein nicht übereinstimmendes Attribut. Diese Einträge sind instanzweit und daher nur für Superuser sichtbar.

Behalten Sie mindestens ein Superuser-Konto mit Benutzername und Passwort als Rückfallebene, und denken Sie daran, dass `/login?force_login_form` das Standard-Anmeldeformular zurückgibt, falls ein Identitätsanbieter nicht mehr funktioniert. Siehe [Single Sign-On](/admin/sso/) für beides.

## Verwandte Themen

* [Single Sign-On](/admin/sso/) — die anbieterspezifischen Einrichtungsanleitungen und Anmeldeeinstellungen
* [Diagnostics](/admin/diagnostics/pro__diagnostics/) — warum ein Anmeldeversuch fehlgeschlagen ist
* [Connectors](/connectors/upstream/about/) — die vorgelagerte Galerie, an der sich diese Seite orientiert
