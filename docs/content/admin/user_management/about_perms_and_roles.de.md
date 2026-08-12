---
title: Berechtigungen in DefectDojo
description: Detaillierte Übersicht aller Berechtigungsoptionen von DefectDojo Pro
weight: 2
audience: pro
aliases:
- /de/en/customize_dojo/user_management/about_perms_and_roles
---

> **DefectDojo-Pro-Funktion.** Das auf dieser Seite beschriebene RBAC-System mit Mitgliedern/Gruppen/globalen Rollen ist Teil von DefectDojo Pro. Open-Source-DefectDojo verwendet das Modell der [Autorisierten Benutzer](../os__authorized_users/) — dort finden Sie Informationen zur Zugriffskontrolle in der Open-Source-Version, sowie die [Hinweise zum 3.0-Upgrade](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization), falls Sie zwischen den Editionen wechseln.

Wenn Sie in DefectDojo mit einem Team von Benutzern arbeiten, ist es wichtig, die rollenbasierte Zugriffskontrolle (Role-Based Access Control, RBAC) angemessen einzurichten, damit Benutzer nur auf bestimmte Daten zugreifen können. Sicherheitsdaten sind hochsensibel, und die Zugriffskontrolloptionen von DefectDojo ermöglichen es Ihnen, den Zugriff jedes Teammitglieds auf Informationen genau festzulegen.

Dieser Artikel bietet einen Überblick darüber, wie Berechtigungen in DefectDojo funktionieren. Wenn Sie stattdessen eine detaillierte Aufschlüsselung **jeder Aktion** sehen möchten, die durch Berechtigungen gesteuert werden kann, lesen Sie unseren Artikel **[Berechtigungsübersicht](../user_permission_chart/)**.

## Arten von Berechtigungen

DefectDojo verwaltet vier verschiedene Arten von Berechtigungen:

* Benutzer können als **Mitglieder** zu **Produkten oder Produkttypen** zugewiesen werden. Eine Produktmitgliedschaft ist mit einer **Rolle** verbunden, die es Ihren Benutzern ermöglicht, Datentypen (Produkttypen, Produkte, Engagements, Tests und Befunde) in DefectDojo anzuzeigen und mit ihnen zu interagieren. Benutzer können mehrere Produkt- oder Produkttyp-Mitgliedschaften mit unterschiedlichen Zugriffsebenen haben.

* Benutzern können außerdem **Konfigurationsberechtigungen** zugewiesen werden, die ihnen den Zugriff auf Konfigurationsseiten in DefectDojo ermöglichen. Konfigurationsberechtigungen stehen in keinem Zusammenhang mit Produkten oder Produkttypen und sind nicht an Rollen gebunden.

* Benutzern können **globale Rollen** zugewiesen werden, die ihnen ein standardisiertes Zugriffsniveau auf alle Produkte und Produkttypen geben.

* Benutzer können als **Superuser** eingerichtet werden: Rollen auf Administratorebene, die ihnen Kontrolle über und Zugriff auf alle DefectDojo-Daten und -Konfigurationen geben.

Jede dieser Berechtigungsarten kann auch einer **Benutzergruppe** zugewiesen werden. Wenn Sie eine große Anzahl an Benutzern in DefectDojo haben, etwa ein dediziertes Testteam für ein bestimmtes Produkt, ermöglichen Ihnen Gruppen, Berechtigungen schnell einzurichten und zu pflegen.

## Produkt-/Produkttyp-Mitgliedschaft & Rollen

Wenn Benutzer als Mitglieder zu einem Produkt oder Produkttyp zugewiesen werden, erhalten sie außerdem eine Rolle, die steuert, wie sie mit den zugehörigen Befund-Daten interagieren.

### Zusammenfassung der Rollen

DefectDojo Pro liefert fünf **integrierte Rollen**: Reader, Writer, Maintainer, Owner und API Importer. Jede davon kann entweder global oder innerhalb eines Produkts / Produkttyps zugewiesen werden.

Die integrierten Rollen sind feste Voreinstellungen. Sie können nicht bearbeitet oder gelöscht werden, und ihre Berechtigungen sind auf jeder DefectDojo-Pro-Instanz identisch. Wenn keine davon zur Arbeitsweise Ihres Teams passt, können Sie eine passende Rolle erstellen, indem Sie einzelne Berechtigungen auswählen oder eine integrierte Rolle klonen und anpassen. Siehe [Benutzerdefinierte RBAC-Rollen](../pro__custom_rbac_roles/).

„Zugrunde liegende Daten“ bezieht sich auf alle Produkte, Engagements, Tests, Befunde oder Endpunkte, die einem Produkt oder Produkttyp untergeordnet sind.

* **Reader**-Benutzer können die zugrunde liegenden Daten jedes Produkts oder Produkttyps, dem sie zugewiesen sind, einsehen und Kommentare hinzufügen. Sie können die zugrunde liegenden Daten weder bearbeiten, hinzufügen noch anderweitig ändern, können jedoch Berichte exportieren und Notizen zu Daten hinzufügen.

* **Writer**-Benutzer verfügen über alle Fähigkeiten von Reader, zusätzlich können sie Engagements, Tests und Befunde hinzufügen oder bearbeiten. Sie können keine neuen Produkte hinzufügen und keine zugrunde liegenden Daten löschen.

* **Maintainer**-Benutzer verfügen über alle Fähigkeiten von Writer, zusätzlich können sie Produkte oder Produkttypen bearbeiten. Sie können dem Produkt oder Produkttyp neue Mitglieder mit Rollen hinzufügen und außerdem Engagements, Tests und Befunde löschen.

* **Owner**-Benutzer haben die größte Kontrolle über ein Produkt oder einen Produkttyp. Sie können andere Owner benennen und außerdem die Produkte oder Produkttypen löschen, denen sie zugewiesen sind.

* **API Importer**-Benutzer verfügen über eingeschränkte Fähigkeiten. Diese Rolle erlaubt eingeschränkten API-Zugriff, ohne den Großteil der API-Endpunkte offenzulegen, und ist daher nützlich für Automatisierung oder Benutzer, die gegenüber DefectDojo „extern“ bleiben sollen. Sie können zugrunde liegende Daten einsehen, Engagements hinzufügen/bearbeiten und Scan-Daten importieren.

Detaillierte Informationen zu den integrierten Rollen finden Sie in unserer **[Rollen-Berechtigungsübersicht](../user_permission_chart/)**. Die vollständige Liste der Berechtigungen, die einer Rolle zugewiesen werden können, sowie Anleitungen zum Erstellen eigener Rollen finden Sie unter **[Benutzerdefinierte RBAC-Rollen](../pro__custom_rbac_roles/)**.

### Globale Rollen

Benutzer mit **globalen Rollen** können je nach zugewiesener Rolle jeden Datentyp (Produkttypen, Produkte, Engagements, Tests und Befunde) in DefectDojo einsehen und mit ihm interagieren.

### Gruppenmitgliedschaften

Benutzergruppen können als Mitglieder eines Produkts oder Produkttyps hinzugefügt werden. Benutzer, die Teil der Gruppe sind, erben den Zugriff auf alle zugehörigen Produkte oder Produkttypen sowie die der Gruppe zugewiesene Rolle.

#### Benutzer mit mehreren Rollen

* Wenn ein Benutzer als Mitglied eines Produkts zugewiesen wird, erhält er standardmäßig keine zugehörigen Produkttyp-Berechtigungen.

* Wenn ein Benutzer für dasselbe Produkt oder denselben Produkttyp mehr als eine Rolle erhält (zum Beispiel eine direkt zugewiesene und eine von einer Gruppe geerbte), erhält er die **kombinierten** Berechtigungen aller Rollen, die er dort innehat.

* Die Produktrolle eines Benutzers hat immer Vorrang vor seiner „Standard“-Produkttyprolle.

* Die Produkt-/Produkttyprolle eines Benutzers hat innerhalb des zugrunde liegenden Produkts oder Produkttyps immer Vorrang vor seiner globalen Rolle. Wenn ein Benutzer beispielsweise die Produkttyprolle Reader hat, aber auch als Owner für ein diesem Produkttyp untergeordnetes Produkt zugewiesen ist, erhält er zusätzliche Owner-Berechtigungen nur für dieses Produkt.

* Rollen können keine Berechtigungen entziehen, sie können nur zusätzliche hinzufügen. Wenn ein Benutzer beispielsweise die Produkttyprolle oder globale Rolle Owner hat, entzieht ihm die Zuweisung der Rolle Reader für ein bestimmtes Produkt nicht seine Owner-Berechtigungen für dieses Produkt.

* Der Superuser-Status hat immer Vorrang vor allen zugewiesenen Rollen.

## Superuser

Superuser (Admins) haben keinerlei Einschränkungen im System. Sie können alle Einstellungen ändern, Benutzer verwalten und haben Lese-/Schreibzugriff auf alle Daten. Sie können außerdem die Zugriffsregeln für alle Benutzer in DefectDojo ändern. Superuser erhalten zudem Benachrichtigungen zu allen Systemproblemen und Warnmeldungen.

Standardmäßig erhält das erste auf einer neuen DefectDojo-Instanz erstellte Konto Superuser-Berechtigungen. Dieser Benutzer kann die Berechtigungen aller später erstellten DefectDojo-Benutzer bearbeiten. Nur ein bestehender Superuser kann einen weiteren Superuser hinzufügen oder einem Benutzer eine globale Rolle zuweisen.

## Konfigurationsberechtigungen

Konfigurationsberechtigungen ähneln zwar Rollen, stehen aber in keinem Zusammenhang mit Produkten oder Rollen. Sie müssen unabhängig von Rollen zugewiesen werden. **Reguläre Benutzer haben standardmäßig keine Konfigurationsberechtigungen, und die Zuweisung dieser Konfigurationsberechtigungen sollte mit Sorgfalt erfolgen.**

Benutzern können Konfigurationsberechtigungen auf unterschiedliche Weise zugewiesen werden:

1. Benutzern können Konfigurationsberechtigungen direkt zugewiesen werden. Bestimmte Berechtigungen können direkt auf einer Benutzerseite konfiguriert werden.

2. Benutzergruppen können Konfigurationsberechtigungen zugewiesen werden. Wie bei Rollen können bestimmte Konfigurationsberechtigungen zu Gruppen hinzugefügt werden, wodurch alle Gruppenmitglieder diese Berechtigungen erhalten.

Superuser verfügen über alle Konfigurationsberechtigungen und haben daher keinen Abschnitt für Konfigurationsberechtigungen auf ihrer Benutzerseite.

### Gruppen-Konfigurationsberechtigungen

Wenn Benutzer Teil einer Gruppe sind, haben sie außerdem Gruppen-Konfigurationsberechtigungen, die ihr Zugriffsniveau auf die Konfiguration einer Gruppe steuern. Gruppenberechtigungen entsprechen nicht der Produkt- oder Produkttyp-Mitgliedschaft der Gruppe.

Wenn Benutzer eine neue Gruppe erstellen, erhalten sie standardmäßig die Rolle Owner für die neue Gruppe.

Weitere Informationen zu Konfigurationsberechtigungen finden Sie in unserer **[Konfigurationsberechtigungsübersicht](../user_permission_chart/#configuration-permission-chart)**.

## Standardberechtigungen verwalten

Wenn in DefectDojo ein völlig neuer Benutzer erstellt wird — ob manuell, per SAML / SSO oder über einen Social-Auth-Anbieter —, hat er **standardmäßig keinerlei Berechtigungen**. Bei der ersten Anmeldung sieht er null Produkttypen, null Produkte und null Engagements. Er kann keine Daten einsehen oder mit ihnen interagieren, bis ein Superuser ihm Zugriff gewährt (direkt, über eine globale Rolle, über eine Produkt-/Produkttyp-Mitgliedschaft oder durch Hinzufügen zu einer Gruppe).

Wenn jeder neu angelegte Benutzer automatisch ein Basiszugriffsniveau erhalten soll — zum Beispiel „jeder neue SSO-Benutzer soll Reader in einer bestimmten Gruppe sein“ —, können Sie auf der Seite System Settings eine **Default group** konfigurieren.

1. Öffnen Sie **⚙️ Configuration → System Settings** (nur Superuser).
2. Legen Sie unter **Default group** die [Benutzergruppe](../create_user_group/) fest, der neu erstellte Benutzer beitreten sollen.
3. Legen Sie unter **Default group role** die Rolle fest, die sie in dieser Gruppe innehaben sollen (z. B. **Reader**).
4. Legen Sie optional unter **Default group email pattern** einen regulären Ausdruck fest (z. B. `.*@yourcompany\.com$`), damit die Standardgruppe nur auf Benutzer angewendet wird, deren E-Mail-Adresse übereinstimmt.
5. Speichern.

Sowohl **Default group** als auch **Default group role** müssen festgelegt sein — ist eines der beiden Felder leer, wird die Standardgruppe nicht angewendet.

Diese Einstellung gilt für jeden Weg der Benutzererstellung: manuelle Erstellung, SAML, OAuth und andere Social-Auth-Anbieter. Sie wird nicht rückwirkend angewendet — bestehende Benutzer behalten ihre aktuellen Gruppenmitgliedschaften, auch wenn Sie diese Einstellung später ändern.

Spezifische Hinweise zu SSO finden Sie unter [SAML-Konfiguration](/admin/sso/pro__saml/#default-access-for-sso-provisioned-users) oder im Abschnitt Ihres Anbieters unter [SSO-Konfiguration](../configure_sso/).
