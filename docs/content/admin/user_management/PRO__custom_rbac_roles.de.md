---
title: Benutzerdefinierte RBAC-Rollen
description: Erstellen Sie eigene Rollen, indem Sie einzelne Berechtigungen auswählen,
  und nutzen Sie die fünf integrierten Rollen als klonbare Ausgangspunkte
weight: 5
audience: pro
---

> **DefectDojo Pro-Funktion.** Das auf dieser Seite beschriebene RBAC-System für Mitglieder/Gruppen/globale Rollen ist Teil von DefectDojo Pro. Open-Source-DefectDojo verwendet das Modell [Authorized Users](../os__authorized_users/). Weitere Informationen zur Zugriffskontrolle in der Open-Source-Version finden Sie auf dieser Seite sowie in den [3.0-Upgrade-Hinweisen](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization), wenn Sie zwischen den Editionen wechseln.

DefectDojo Pro wird mit fünf Rollen ausgeliefert: **Reader**, **Writer**, **Maintainer**, **Owner** und **API Importer**. Falls keine davon passt, können Sie jetzt Ihre eigene Rolle erstellen, indem Sie genau festlegen, welche Berechtigungen sie gewährt.

Eine benutzerdefinierte Rolle funktioniert überall dort, wo auch eine integrierte Rolle funktioniert: als globale Rolle, als Rolle einer Gruppe, als Standard-Gruppenrolle und als Mitgliedsrolle für eine einzelne Organisation oder ein einzelnes Asset.

Die fünf integrierten Rollen werden zu **gesperrten, klonbaren Vorlagen**. Ihre Berechtigungen bleiben unverändert (siehe die [Tabellen der Aktionsberechtigungen](../user_permission_chart/) für die jeweils gewährten Rechte), sie können weder bearbeitet noch gelöscht werden, und das Klonen einer solchen Rolle ist der empfohlene Weg, um eine neue Rolle zu erstellen.

## Bevor Sie beginnen

Die Verwaltung benutzerdefinierter Rollen ist standardmäßig deaktiviert. Ein **Superuser** aktiviert sie unter **Settings > Feature Flags**, indem er **Custom Roles** einschaltet. Wie diese Seite funktioniert, erfahren Sie unter [Feature Flags](/admin/feature_flags/pro__feature_flags/).

Solange die Funktion deaktiviert ist, bleibt die Seite „Rollen" weiterhin lesbar: Sie können die integrierten Rollen und ihre Berechtigungen einsehen, aber nichts erstellen, bearbeiten, klonen oder löschen.

Die Verwaltung von Rollen erfordert den **Superuser**-Status oder die integrierte globale Rolle **Owner**. Dies ist beabsichtigt und kann nicht an eine benutzerdefinierte Rolle delegiert werden: siehe [Was eine benutzerdefinierte globale Rolle freischaltet](#what-a-custom-global-role-unlocks).

## Öffnen der Seite „Rollen"

Gehen Sie in der linken Seitenleiste zu **👤 Users > Roles**. Der Menüeintrag ist für Superuser und Inhaber der integrierten globalen Rolle Owner sichtbar.

![Die Seite „Rollen" mit integrierten und benutzerdefinierten Rollen](images/pro_roles_list.png)

Die Tabelle listet alle Rollen Ihrer Instanz auf:

| Column | What it shows |
| --- | --- |
| **ID** | Die numerische ID der Rolle. Nützlich beim Filtern der Benutzertabelle oder beim Aufruf der API. |
| **Name** | Der Name der Rolle. |
| **Description** | Ihre eigene Notiz dazu, wofür die Rolle gedacht ist. Optional und leer, sofern sie niemand ausfüllt. Die integrierten Rollen werden ohne Beschreibung ausgeliefert. |
| **Permissions** | Eine Anzahl der gewährten Berechtigungen. Klicken Sie darauf, um eine schreibgeschützte Ansicht des gesamten Rasters zu öffnen. |
| **Users** | Wie viele Benutzer diese Rolle als globale Rolle innehaben. Klicken Sie durch, um sie in der Benutzertabelle zu sehen. |
| **Type** | **Built-in** für die fünf Vorlagen, **Custom** für selbst erstellte Rollen. |

Jede Spalte ist sortier- und filterbar, und die Stichwortsuche durchsucht Name und Beschreibung.

## Erstellen einer Rolle

### Eine integrierte Rolle klonen (empfohlen)

Das Klonen startet mit einem bewährten Berechtigungssatz anstelle eines leeren Rasters, wodurch es viel schwerer wird, versehentlich eine Berechtigung zu vergessen, die eine Rolle benötigt.

1. Suchen Sie die Rolle, die Ihrem Bedarf am nächsten kommt.
2. Öffnen Sie deren **⋮**-Menü und wählen Sie **Clone Role**.
3. Eine Kopie wird sofort erstellt, benannt `<original> (copy)`, mit denselben Berechtigungen und derselben Beschreibung wie die Rolle, von der sie stammt.
4. Öffnen Sie das **⋮**-Menü der Kopie, wählen Sie **Edit Role**, benennen Sie sie dann um und passen Sie ihre Berechtigungen an.

Integrierte Rollen können geklont werden, obwohl sie nicht bearbeitet werden können. Der Klon speichert, von welcher Rolle er stammt.

### Von Grund auf neu erstellen

1. Klicken Sie auf **New Role**.
2. Geben Sie ihr einen **Name** (erforderlich) und optional eine **Description**.
3. Wählen Sie ihre Berechtigungen im Raster unten aus (siehe nächster Abschnitt).
4. Klicken Sie auf **Save Role**.

Rollennamen müssen eindeutig sein, wobei die Prüfung Groß-/Kleinschreibung ignoriert: Existiert bereits `Triage Lead`, wird `triage lead` abgelehnt.

## Berechtigungen auswählen

![Das Berechtigungsraster im Rollenformular](images/pro_role_permission_grid.png)

Die Berechtigungen sind in drei Tabellen plus eine Checkliste gruppiert.

**Object Permissions** gelten für die Organisationen und Assets, denen die Rolle zugewiesen ist, sowie für alles, was darunter verschachtelt ist.

| Row | View | Add | Edit | Delete |
| --- | --- | --- | --- | --- |
| Organization | ☑️ | ☑️ | ☑️ | ☑️ |
| Asset | ☑️ | ☑️ ¹ | ☑️ | ☑️ |
| Engagement | ☑️ | ☑️ | ☑️ | ☑️ |
| Test | ☑️ | ☑️ | ☑️ | ☑️ |
| Finding | ☑️ | ☑️ | ☑️ | ☑️ |
| Finding Group | ☑️ | ☑️ | ☑️ | ☑️ |
| Risk Acceptance | ☑️ | ☑️ | ☑️ | ☑️ |
| Location | ☑️ | ☑️ | ☑️ | ☑️ |
| Component | ☑️ | | | |
| Note | ² | ☑️ | ☑️ | ☑️ |
| Benchmark | ² | | ☑️ | ☑️ |
| Language | ☑️ | ☑️ | ☑️ | ☑️ |
| Technology | ☑️ | ☑️ | ☑️ | ☑️ |
| Asset API Scan Configuration | ☑️ | ☑️ | ☑️ | ☑️ |
| Asset Tracking Files | ☑️ | ☑️ | ☑️ | ☑️ |
| Group | ☑️ | | ☑️ | ☑️ |

1. **Asset > Add** bedeutet das Erstellen eines neuen Assets innerhalb einer Organisation, der die Rolle zugewiesen ist.
2. Die Ansicht für Notes und Benchmarks wird vererbt: Eine Rolle, die das übergeordnete Engagement, den Test, den Finding oder das Asset anzeigen kann, kann auch dessen Notes und Benchmarks anzeigen. Diese Zellen zeigen ein **?**-Symbol anstelle eines Kontrollkästchens.

**Group & Member Permissions** steuern, wer die Mitgliedschaft verwalten kann. Die Spalten hier sind View, Manage, Add, Add Owner, Edit und Delete.

| Row | Available actions |
| --- | --- |
| Organization Group, Asset Group | View, Add, Add Owner, Edit, Delete |
| Organization Member, Asset Member, Group Member | Manage, Add Owner, Delete |

**Global Feature Permissions** steuern instanzweite Pro-Funktionen und nicht einzelne Organisationen oder Assets, daher **wirken sie nur, wenn die Rolle als globale Rolle vergeben ist**. Werden sie einer Rolle gewährt, die nur als Asset-Mitgliedschaft verwendet wird, hat das keine Wirkung.

| Row | Available actions |
| --- | --- |
| Report Template | View, Add, Edit, Delete |
| Generated Report | View, Add, Delete |
| Connector, Sensei, Asset Hierarchy, Version Manager, Tuner, Universal Parser, Rule, Integration | View, Edit |
| Mitigation Policy | Edit |
| Audit Log, Metering | View |

**Additional Permissions** ist eine Checkliste von Fähigkeiten, die nicht in das Schema View/Add/Edit/Delete passen:

* **Configure Asset Notifications**: festlegen, welche Benachrichtigungen ein einzelnes Asset sendet und wohin.
* **Import Scan Result**: Scan-Ergebnisse importieren und erneut importieren, wodurch Findings erstellt und aktualisiert werden.
* **Share Dashboard Layout**: ein Dashboard-Layout für andere Benutzer veröffentlichen. Nur als globale Rolle.
* **Share Table Preference**: eine gespeicherte Tabellenansicht (Spalten, Filter, Sortierreihenfolge) veröffentlichen. Nur als globale Rolle.
* **View Note History**: sehen, wer eine Note wann geändert hat.

### So lesen Sie das Raster

![Die schreibgeschützte Ansicht der Berechtigungen einer Rolle](images/pro_role_permissions_modal.png)

| What you see | What it means |
| --- | --- |
| Ein leeres Kontrollkästchen | Die Berechtigung existiert und ist nicht gewährt. Klicken Sie, um sie zu gewähren. |
| Ein aktiviertes Kontrollkästchen | Gewährt. |
| Eine schattierte, leere Zelle | Die Berechtigung existiert für diese Zeile und Aktion nicht. Nicht auswählbar. |
| Ein **?**-Symbol | Die Ansicht wird von einem übergeordneten Objekt vererbt, hier gibt es also nichts zu gewähren. |
| Ein grünes ✔ (schreibgeschützte Ansicht) | Gewährt. |
| Ein rotes ✘ (schreibgeschützte Ansicht) | Nicht gewährt. |

In jeder Zeile steuert die am weitesten links stehende Berechtigung (**View**, bei Mitgliederzeilen **Manage**) den Rest der Zeile. Sie müssen sie gewähren, bevor die übrigen Zellen dieser Zeile verfügbar werden, denn eine Rolle kann nicht sinnvoll bearbeiten oder löschen, was sie nicht sehen kann. Wird die steuernde Berechtigung entfernt, werden auch die übrigen Berechtigungen der Zeile entfernt.

## Bearbeiten, Klonen und Löschen

Das **⋮**-Menü jeder Zeile bietet **Edit Role**, **Clone Role**, **Delete Role** und **Role History**.

Integrierte Rollen bieten nur **Clone Role**. Sie können von niemandem bearbeitet oder gelöscht werden, auch nicht von Superusern. Dadurch bleibt eine bekannte Ausgangsbasis erhalten und Upgrades bleiben vorhersehbar.

Das Löschen einer Rolle, die noch jemandem zugewiesen ist, schlägt fehl. Weisen Sie diese Zuweisungen zunächst um oder entfernen Sie sie, und löschen Sie die Rolle erst danach. Als Zuweisungen zählen dabei Organisations- und Asset-Mitgliedschaften (sowohl für Benutzer als auch für Gruppen), globale Rollen, Gruppenmitgliedschaften sowie die Standard-Gruppenrolle in den Systemeinstellungen.

Die API kann die Neuzuweisung für Sie in einem einzigen Aufruf durchführen. Siehe [Verwalten von Rollen über die API](#managing-roles-through-the-api).

## Zuweisen einer benutzerdefinierten Rolle

Benutzerdefinierte Rollen erscheinen in jedem Rollen-Dropdown, neben den integrierten Rollen:

| Where | How |
| --- | --- |
| **Global Role on a user** | Das Feld **Global Role** im Formular des Benutzers. Nur für Superuser. Siehe [Berechtigungen eines Benutzers festlegen](../set_user_permissions/). |
| **Global Role on a group** | Das Feld **Global Role** im Formular der Gruppe. Siehe [Berechtigungen teilen: Benutzergruppen](../create_user_group/). |
| **Organization or Asset membership** | Der Berechtigungsdialog der Organisation oder des Assets, sowohl für Benutzer als auch für Gruppen. Siehe [Berechtigungen in Pro festlegen](../pro_permissions_overhaul/). |
| **Default group role** | **Default group role** in den Systemeinstellungen, angewendet auf neu erstellte Benutzer. Siehe [Standardberechtigungen verwalten](../about_perms_and_roles/#manage-default-permissions). |
| **Role within a group** | Das Rollen-Dropdown in der Mitgliederliste einer Gruppe. Dieses Dropdown bietet nur Rollen an, die mindestens eine Group-Berechtigung gewähren; eine Rolle ohne Group-Berechtigungen erscheint dort also nicht. |

Zwei Einschränkungen sind wichtig zu wissen:

* **Die Owner-Stufe ist reserviert.** Eine benutzerdefinierte Rolle kann niemals eine Rolle der Owner-Stufe sein. Nur die integrierte Owner-Rolle ist das, weshalb nur sie die implizite Macht besitzt, andere Owner zu verwalten.
* **Um jemand anderem die Owner-Rolle zu gewähren, ist weiterhin die passende Add-Owner-Berechtigung erforderlich**, unabhängig davon, ob Sie dies bei einer Organisation, einem Asset oder einer Gruppe tun.

## Was eine benutzerdefinierte globale Rolle freischaltet

Teile der Benutzeroberfläche sind an eine Mindest-Globalrolle gebunden statt an eine einzelne Berechtigung. Damit benutzerdefinierte Rollen mit diesen Schranken funktionieren, ordnet DefectDojo eine benutzerdefinierte globale Rolle den integrierten Stufen zu: Eine benutzerdefinierte Rolle erreicht die höchste Stufe, deren Berechtigungen sie **vollständig** abdeckt.

* Eine benutzerdefinierte Rolle, die alles abdeckt, was Maintainer gewährt, wird für diese Schranken wie Maintainer behandelt.
* Deckt sie alles ab, was Writer gewährt, wird sie wie Writer behandelt. Ebenso für Reader.
* Deckt sie keine davon vollständig ab, erreicht sie keine Stufe. Ihre einzelnen Berechtigungen funktionieren weiterhin genau wie gewährt; nur die stufenbasierten UI-Schranken bleiben verschlossen.
* **Owner kann auf diesem Weg nie erreicht werden.** Die Rollenverwaltung und alles andere, was an die globale Owner-Rolle gebunden ist, bleibt Superusern und der integrierten Owner-Rolle vorbehalten.

Die Abdeckung muss vollständig sein, was gelegentlich überrascht. Eine von Maintainer geklonte Rolle erreicht die Maintainer-Stufe. Bauen Sie die Berechtigungen von Maintainer von Hand nach und übersehen dabei eine, landet die Rolle stattdessen auf der Writer-Stufe. Fehlt bei einer benutzerdefinierten globalen Rolle eine erwartete UI-Funktion, vergleichen Sie sie mit der integrierten Stufe in den [Tabellen der Aktionsberechtigungen](../user_permission_chart/).

## Rollenverlauf

Benutzerdefinierte Rollen führen ein Prüfprotokoll. Öffnen Sie **Role History** über das **⋮**-Menü einer Rolle, um zu sehen, welche Berechtigungen von wem und wann gewährt oder entzogen wurden, zusammen mit Änderungen daran, wer die Rolle innehat.

Zwei Dinge zeigt dieser Verlauf nicht: Änderungen am Namen und an der Beschreibung einer Rolle selbst sowie die Berechtigungen integrierter Rollen (diese werden vorab angelegt, nie bearbeitet und erzeugen daher nie einen Verlauf).

Der Rollenverlauf ist ein Lesevorgang und daher unabhängig davon verfügbar, ob die Custom-Roles-Funktion aktiviert ist.

## Verwalten von Rollen über die API

Rollen sind unter `/api/v2/roles/` verfügbar. Lesezugriffe stehen jedem authentifizierten Benutzer offen, da Clients die Rollenliste benötigen, um Dropdowns zu befüllen. Schreibzugriffe erfordern den Superuser-Status oder die integrierte globale Owner-Rolle sowie das Custom-Roles-Feature-Flag.

| Operation | Request |
| --- | --- |
| List roles | `GET /api/v2/roles/` |
| Retrieve one role | `GET /api/v2/roles/{id}/` |
| List every grantable permission | `GET /api/v2/roles/permissions_catalog/` |
| Create a role | `POST /api/v2/roles/` mit `name`, optional `description` und einer `permissions`-Liste |
| Replace a role's permissions | `PATCH /api/v2/roles/{id}/` mit einer `permissions`-Liste |
| Clone a role | `POST /api/v2/roles/{id}/clone/` mit optionalem `name` und `description` |
| Delete a role | `DELETE /api/v2/roles/{id}/` |
| Delete a role and move its assignments | `DELETE /api/v2/roles/{id}/?reassign_to={other_role_id}` |
| Read a role's history | `GET /api/v2/roles/{id}/history/` |

Hinweise:

* `permissions` **ersetzt** die Berechtigungsliste der Rolle, statt sie zu ergänzen. Senden Sie die vollständige Menge, die die Rolle am Ende haben soll.
* `?reassign_to=` verschiebt alle Zuweisungen der gelöschten Rolle in einer einzigen Transaktion auf die von Ihnen genannte Rolle. Dies ist der einzige Weg für eine Massen-Neuzuweisung: Die Benutzeroberfläche bietet dies nicht an.
* Der Versuch, eine integrierte Rolle zu bearbeiten oder zu löschen, liefert `403`. Das Bearbeiten eines unbekannten Berechtigungswerts, die Wiederverwendung eines bestehenden Rollennamens oder das Löschen einer verwendeten Rolle ohne `reassign_to` liefert `400` mit einer Erklärung.
* `is_owner` kann nicht über die API gesetzt werden. Wird es dennoch gesendet, wird es akzeptiert und ignoriert.

## Wissenswertes

* **Mehrere Rollen am selben Objekt gewähren die Vereinigung ihrer Berechtigungen.** Hält ein Benutzer direkt eine Rolle an einem Asset und erbt über eine Gruppe eine weitere, erhält er alles, was beide Rollen gewähren. Rollen fügen Berechtigungen immer nur hinzu, nie entziehen sie welche.
* **Berechtigungsänderungen werden beim nächsten Laden der Seite übernommen**, nicht sofort in der aktuellen Ansicht. Hintergrundjobs können bis zu 30 Sekunden brauchen, zwischengespeicherte Berechtigungsdaten bis zu 5 Minuten, bis eine Änderung sichtbar wird.
* **Rollen-Dropdowns listen bis zu 250 Rollen auf.** Darüber hinaus erscheinen manche Rollen nicht mehr in Dropdowns, funktionieren aber weiterhin.
* **Maintainer und Owner können Organizations hinzufügen, das Raster zeigt dies jedoch nicht.** Bei diesen beiden Rollen ist diese Gewährung als globale Gewährung gespeichert, und das Raster liest nur objektbezogene Gewährungen, weshalb ihre Zelle **Organization > Add** als nicht gewährt angezeigt wird. Das Klonen einer der beiden Rollen übernimmt die Gewährung.
* **Die Terminologie folgt Ihrer Instanz.** Diese Dokumentation verwendet Organization und Asset, die Standardbezeichnungen. Wurde die Umbenennung Organization/Asset in Ihrer Instanz deaktiviert, lauten dieselben Zeilen stattdessen Product Type und Product.
* **Die Seite „Rollen" ist für alle anderen schreibgeschützt.** Ein Benutzer, der direkt `/settings/roles` aufruft, kann die Rollen und ihre Berechtigungen sehen, aber nichts ändern. Berechtigungsdaten sind nicht sensibel, und der Server setzt die eigentliche Grenze bei jedem Schreibvorgang durch.
