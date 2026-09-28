---
title: Benutzerverwaltung
description: Benutzer, Zugriffskontrolle und Authentifizierung in DefectDojo verwalten
summary: ''
date: 2023-09-07 16:06:50+02:00
lastmod: 2023-09-07 16:06:50+02:00
draft: false
weight: 5
chapter: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
exclude_search: true
---

Die Benutzerverwaltung von DefectDojo unterscheidet sich je nach Edition. Wählen Sie den Abschnitt, der zu Ihrer Installation passt.

## DefectDojo Open-Source

Open-Source-DefectDojo verwendet das Modell der **Autorisierten Benutzer**: Ein Benutzer erhält Zugriff auf ein Produkt oder einen Produkttyp, indem er zur Liste der Autorisierten Benutzer dieses Datensatzes hinzugefügt wird. Superuser und Mitarbeiter können alles sehen.

* [Autorisierte Benutzer](./os__authorized_users/) — wie Sie Zugriff auf Produkte und Produkttypen gewähren

Die Authentifizierung bei Open-Source-DefectDojo erfolgt über lokalen Benutzernamen/Passwort sowie den Passwort-Reset-Ablauf.

## DefectDojo Pro

DefectDojo Pro verwendet ein rollenbasiertes System mit Mitgliedern, Gruppen und globalen Rollen. Benutzer können außerdem SSO-Zugriff über SAML oder einen der unterstützten OAuth-Anbieter erhalten.

* [Berechtigungen in DefectDojo](./about_perms_and_roles/) — Überblick über Rollen, Mitgliedschaften, globale Rollen und Konfigurationsberechtigungen
* [Berechtigungen eines Benutzers festlegen](./set_user_permissions/) — Zuweisen von Rollen, globalen Rollen und Konfigurationsberechtigungen
* [Berechtigungen teilen: Benutzergruppen](./create_user_group/) — Berechtigungen für viele Benutzer gleichzeitig zuweisen
* [Berechtigungen in Pro festlegen](./pro_permissions_overhaul/) — Pro-spezifische Benutzeroberfläche zur Verwaltung von Mitgliedern und Berechtigungen
* [Massenhaftes Zurücksetzen von Benutzeranmeldedaten](./pro__resetting_user_credentials/) — API-Tokens rotieren und Passwort-Resets für viele Benutzer gleichzeitig erzwingen
* [Aktions-Berechtigungsübersichten](./user_permission_chart/) — vollständige Referenz aller Berechtigungen für jede integrierte Rolle
* [Benutzerdefinierte RBAC-Rollen](./pro__custom_rbac_roles/) — eigene Rollen durch Auswahl einzelner Berechtigungen erstellen
* [Single Sign-On](/admin/sso/) — SAML- und OAuth-Einrichtung für Pro

## Wechsel zwischen Editionen

Wenn Sie von den Autorisierten Benutzern der Open-Source-Version zum RBAC von Pro wechseln, oder von einer Open-Source-Version vor 3.0, die RBAC verwendet hat, auf das aktuelle Modell der Autorisierten Benutzer aktualisieren, lesen Sie die [Hinweise zum 3.0-Upgrade](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization). Bestehende Zugriffsrechte bleiben automatisch erhalten.
