---
title: Berechtigungen eines Benutzers festlegen
description: So gewähren Sie einem Benutzer Rollen und Berechtigungen sowie Superuser-Status
weight: 2
audience: pro
aliases:
- /en/customize_dojo/user_management/set_user_permissions
---

> **DefectDojo Pro-Funktion.** Das auf dieser Seite beschriebene RBAC-System für Mitglieder/Gruppen/Globale Rollen ist Teil von DefectDojo Pro. Open-Source-DefectDojo verwendet das Modell [Autorisierte Benutzer](../os__authorized_users/) — siehe diese Seite für die Zugriffskontrolle in der Open-Source-Version sowie die [3.0-Upgrade-Hinweise](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization), wenn Sie zwischen den Editionen wechseln.

## Einführung in die Berechtigungstypen

Einzelne Benutzer können vier verschiedene Arten von Berechtigungen zugewiesen bekommen:

* Benutzer können als **Mitglieder von Produkten oder Produkttypen** zugewiesen werden. Dies ermöglicht ihnen, je nach der ihnen für das jeweilige Produkt zugewiesenen Rolle, Datentypen (Produkttypen, Produkte, Engagements, Tests und Befunde) in DefectDojo anzuzeigen und mit ihnen zu interagieren. Benutzer können mehrere Produkt- oder Produkttyp-Mitgliedschaften mit unterschiedlichen Zugriffsebenen haben.

* Benutzern können außerdem **Konfigurationsberechtigungen** zugewiesen werden, die ihnen Zugriff auf Konfigurationsseiten in DefectDojo gewähren. Konfigurationsberechtigungen stehen in keinem Zusammenhang mit Produkten oder Produkttypen.

* Benutzern können **Globale Rollen** zugewiesen werden, die ihnen ein standardisiertes Zugriffsniveau auf alle Produkte und Produkttypen gewähren.

* Benutzer können als **Superuser** eingerichtet werden: Administratorrollen, die ihnen Kontrolle über und Zugriff auf alle Daten und Konfigurationen von DefectDojo geben.

Sie können auch Gruppen erstellen, wenn Sie einer Gruppe von Benutzern gleichzeitig Produktmitgliedschaft, Konfigurationsberechtigungen oder Globale Rollen zuweisen möchten. Wenn Sie eine große Anzahl von Benutzern in DefectDojo haben, etwa ein dediziertes Testteam für ein bestimmtes Produkt, können Gruppen eine hilfreichere Funktion sein.

## Superuser \& Globale Rollen

Ein Teil Ihrer Rollenbasierten Zugriffskontrolle (RBAC)-Konfiguration erfordert möglicherweise die Erstellung zusätzlicher Superuser oder Benutzer mit Globalen Rollen.

* Superuser (Admins) unterliegen keinerlei Einschränkungen im System. Sie können alle Einstellungen ändern, Benutzer verwalten und haben Lese-/Schreibzugriff auf alle Daten. Sie können auch Zugriffsregeln für alle Benutzer in DefectDojo ändern. Superuser erhalten außerdem Benachrichtigungen zu allen Systemproblemen und -warnungen.
* Benutzer mit Globalen Rollen können je nach ihrer zugewiesenen Rolle jeden Datentyp (Produkttypen, Produkte, Engagements, Tests und Befunde) in DefectDojo anzeigen und mit ihm interagieren. Weitere Informationen zu den einzelnen Rollen und den damit verbundenen Berechtigungen finden Sie in unserem Artikel „Einführung in die Rollen".
* Benutzern können außerdem bestimmte Konfigurationsberechtigungen zugewiesen werden, die ihnen Zugriff auf bestimmte Konfigurationsseiten von DefectDojo gewähren. Benutzer haben standardmäßig keine Konfigurationsberechtigungen.

Standardmäßig erhält das erste auf einer neuen DefectDojo-Instanz erstellte Konto Superuser-Berechtigungen. Dieser Benutzer kann die Berechtigungen für alle nachfolgenden DefectDojo-Benutzer bearbeiten. Nur ein bestehender Superuser kann einen weiteren Superuser hinzufügen oder einem Benutzer eine Globale Rolle zuweisen.

### Einem bestehenden Benutzer den Status Superuser oder Globale Rolle hinzufügen

1. Navigieren Sie in der Seitenleiste zur Seite 👤 Benutzer \> Benutzer. Sie sehen eine Liste aller registrierten Konten in DefectDojo, zusammen mit dem Aktiv-Status, den Globalen Rollen und weiteren relevanten Benutzerdaten des jeweiligen Kontos.

![image](images/Set_a_User's_Permissions.png)

2. Klicken Sie auf den Namen des Kontos, dem Sie Superuser-Berechtigungen erteilen möchten. Dadurch gelangen Sie auf die Benutzerseite dieses Kontos.

3. Öffnen Sie im Abschnitt „Standardinformationen" der Benutzerseite das ☰-Menü und wählen Sie Bearbeiten.

![image](images/Set_a_User's_Permissions_2.png)

4. Auf der Seite „Benutzer bearbeiten":

Aktivieren Sie für den Superuser-Status das Kontrollkästchen ☑️ Superuser-Status, das sich in den Standardinformationen des Benutzers befindet.

Um eine Globale Rolle zuzuweisen, wählen Sie im Dropdown-Menü „Globale Rolle" am unteren Rand der Seite eine Rolle aus.

![image](images/Set_a_User's_Permissions_3.png)

5. Klicken Sie auf Absenden, um diese Änderungen zu übernehmen.

## Produkt- \& Produkttyp-Mitgliedschaft

Standardmäßig hat jedes neu erstellte Konto in DefectDojo keine Berechtigung, Daten auf Produktebene anzuzeigen. Diese Konten müssen jedem Produkt, das sie anzeigen und mit dem sie interagieren möchten, als Mitglied zugewiesen werden.

* Die Produkt- \& Produkttyp-Mitgliedschaft kann nur von **Superusern, Maintainern oder Ownern** konfiguriert werden.
* **Maintainer \& Owner** können die Mitgliedschaft nur für Produkte/Produkttypen konfigurieren, denen sie bereits zugewiesen sind.
* **Globale Maintainer \& Owner** können die Mitgliedschaft für jedes Produkt oder jeden Produkttyp konfigurieren, ebenso wie **Superuser**.

Benutzer können auf **Produkt**-Ebene gleichzeitig zwei Arten von Mitgliedschaft haben:

* Die Rolle, die ihnen durch ihre zugrunde liegende Produkttyp-Mitgliedschaft verliehen wird, falls zutreffend
* Ihre produktspezifische Rolle, falls vorhanden.

Wenn ein Benutzer bereits als Produkttyp-Mitglied hinzugefügt wurde und keine zusätzliche Berechtigungsebene für ein bestimmtes Produkt benötigt, ist es nicht nötig, ihn als Produktmitglied hinzuzufügen.

### Ein neues Mitglied hinzufügen

1. Navigieren Sie zu dem Produkt oder Produkttyp, dem Sie einen Benutzer zuweisen möchten. Sie können das Produkt aus der Liste unter **Produkte \> Alle Produkte** auswählen.

![image](images/Set_a_User's_Permissions_4.png)

2. Suchen Sie die Überschrift **Mitglieder**, klicken Sie auf das Menü **☰** und wählen Sie **\+ Benutzer hinzufügen**.
3. Dadurch gelangen Sie auf eine Seite, auf der Sie **neue Mitglieder registrieren** können. Wählen Sie einen Benutzer aus dem Dropdown-Menü „Benutzer" aus.
4. Wählen Sie die Rolle aus, die dieser Benutzer für dieses Produkt oder diesen Produkttyp haben soll: **API Importer, Reader, Writer, Maintainer** oder **Owner.**

![image](images/Set_a_User's_Permissions_5.png)

Benutzer können einem Produkt oder Produkttyp nicht als Mitglied zugewiesen werden, ohne auch eine Rolle zu erhalten. Wenn Sie nicht sicher sind, welche Rolle Sie einem neuen Benutzer zuweisen möchten, ist **Reader** eine gute „Standard"-Option. Dadurch bleibt der Zustand Ihres Produkts sicher, bis Sie Ihre endgültige Entscheidung über die Rolle getroffen haben.

### Ein Mitglied bearbeiten oder löschen

Die Rolle von Mitgliedern kann innerhalb eines Produkts oder Produkttyps geändert werden.

Navigieren Sie auf der Seite **Produkt** oder **Produkttyp** zur Überschrift **Mitglieder** und klicken Sie auf die Schaltfläche **⋮** neben dem Benutzer, den Sie bearbeiten oder löschen möchten.

![image](images/Set_a_User's_Permissions_6.png)

📝 **Bearbeiten** führt Sie zum Bildschirm **Mitglied bearbeiten**, auf dem Sie die **Rolle** dieses Benutzers ändern können (von **API Importer, Reader, Writer, Maintainer** oder **Owner** zu einer anderen Auswahl).

🗑️ **Löschen** entfernt die Mitgliedschaft eines Benutzers vollständig. Dadurch werden keine Beiträge oder Änderungen entfernt, die der Benutzer am Produkt oder Produkttyp vorgenommen hat.

* Wenn Sie die Mitgliedschaft eines Benutzers nicht bearbeiten oder löschen können (das Symbol **⋮** ist nicht sichtbar), liegt das daran, dass diese Mitgliedschaft auf **Produkttyp**-Ebene verliehen wurde.
* Ein Benutzer kann innerhalb eines Produkts zwei Mitgliedschaftsebenen haben \- eine auf **Produkttyp**-Ebene zugewiesene und eine weitere auf **Produkt**-Ebene zugewiesene.

#### Einem Benutzer mit einer zugehörigen Produkttyp-Rolle eine zusätzliche Produktrolle hinzufügen

Wenn ein Benutzer eine Rolle auf Produkttyp-Ebene hat, wird ihm auch für jedes zugrunde liegende Produkt innerhalb dieser Kategorie eine Mitgliedschaft mit dieser Rolle zugewiesen. Wenn dieser Benutzer jedoch für ein bestimmtes Produkt innerhalb dieses Produkttyps eine besondere Rolle haben soll, können Sie ihm auf Produktebene eine zusätzliche Rolle geben.

1. Navigieren Sie auf der Produktseite zur Überschrift **Mitglieder**, klicken Sie auf das Menü **☰** und wählen Sie **\+ Benutzer hinzufügen** (so, als würden Sie einen neuen Benutzer zum Produkt hinzufügen).
2. Wählen Sie den Namen des Benutzers aus dem Dropdown-Menü aus und wählen Sie die Produktrolle, die diesem Benutzer zugewiesen werden soll.

Eine Produktrolle setzt die Standard-Produkttyp-Rolle oder Globale Rolle eines Benutzers außer Kraft. Wenn ein Benutzer beispielsweise eine Produkttyp-Rolle als **Reader** hat, aber auch als **Owner** für ein unter diesem Produkttyp verschachteltes Produkt zugewiesen ist, erhält er nur für dieses Produkt zusätzliche **Owner**-Berechtigungen.

Dies funktioniert jedoch nicht umgekehrt. Wenn ein Benutzer eine Produkttyp-Rolle oder Globale Rolle als **Owner** hat, entzieht ihm die Zuweisung einer **Reader**-Rolle für ein bestimmtes Produkt nicht seine **Owner**-Berechtigungen. **Rollen können einem Benutzer keine durch andere Rollen gewährten Berechtigungen entziehen, sie können nur zusätzliche Berechtigungen hinzufügen.**

## Konfigurationsberechtigungen

Viele Konfigurationsdialoge und API-Endpunkte können für Benutzer oder Benutzergruppen aktiviert werden, unabhängig von deren Superuser-Status. Diese Konfigurationsberechtigungen ermöglichen es regulären Benutzern, auf Teile von DefectDojo außerhalb ihrer standardmäßigen Produkt- oder Produktrollen-Zuweisung zuzugreifen und zu diesen beizutragen.

Konfigurationsberechtigungen stehen in keinem Zusammenhang mit einem bestimmten Produkt oder Produkttyp \- Benutzern können Konfigurationsberechtigungen zugewiesen werden, ohne dass andere Status oder eine Produkt-/Produkttyp-Mitgliedschaft erforderlich sind.

### Liste der Konfigurationsberechtigungen

* **Credential Manager:** Zugriff auf die Seite ⚙️Konfiguration \> Credential Manager
* **Entwicklungsumgebungen:** Verwaltung der Liste Engagements \> Umgebungen
* **Finding-Vorlagen:** Zugriff auf die Seite Befunde \> Finding-Vorlagen
* **Gruppen**: Zugriff auf die Seite 👤Benutzer \> Gruppen
* **Jira-Instanzen:** Zugriff auf die Seite ⚙️Konfiguration \> JIRA
* **Sprachtypen**: Zugriff auf den [Language Types](/automation/api/languages/)-API-Endpunkt
* **Login-Banner**: Bearbeiten der Seite ⚙️Konfiguration \> Login-Banner
* **Ankündigungen**: Zugriff auf ⚙️Konfiguration \> Ankündigungen
* **Notiztypen:** Zugriff auf die Seite ⚙️Konfiguration \> Notiztypen
* **Produkttypen:** entfällt
* **Fragebögen**: Zugriff auf die Seite Fragebögen \> Alle Fragebögen
* **Fragen**: Zugriff auf die Seite Fragebögen \> Fragen
* **Regularien**: Zugriff auf die Seite ⚙️Konfiguration \> Regularien
* **SLA-Konfiguration:** Zugriff auf die Seite ⚙️Konfiguration \> SLA-Konfiguration
* **Testtypen:** Hinzufügen oder Bearbeiten eines Testtyps (unter Engagements \> Testtypen)
* **Tool-Konfiguration:** Zugriff auf die Seite **⚙️Konfiguration \> Tool-Typen**
* **Tool-Typen:** Zugriff auf die Seite ⚙️Konfiguration \> Tool-Typen
* **Benutzer:** Zugriff auf die Seite 👤Benutzer \> Benutzer

### Konfigurationsberechtigungen zu einem Benutzer hinzufügen

**Nur Superuser können einem Benutzer Konfigurationsberechtigungen hinzufügen**.

1. Navigieren Sie in der Seitenleiste zur Seite 👤 Benutzer \> Benutzer. Sie sehen eine Liste aller registrierten Konten in DefectDojo, zusammen mit dem Aktiv-Status, den Globalen Rollen und weiteren relevanten Benutzerdaten des jeweiligen Kontos.

![image](images/Set_a_User's_Permissions_7.png)

2. Klicken Sie auf den Namen des Kontos, das Sie bearbeiten möchten.

3. Navigieren Sie zur Liste der Konfigurationsberechtigungen. Diese befindet sich auf der rechten Seite der Benutzerseite.

4. Wählen Sie die Benutzerkonfigurationsberechtigungen aus, die Sie hinzufügen möchten.

Eine detaillierte Aufschlüsselung der Benutzerkonfigurationsberechtigungen finden Sie in unserer [Berechtigungsübersicht](../user_permission_chart/).
