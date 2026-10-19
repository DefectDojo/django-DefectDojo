---
title: 'Berechtigungen teilen: Benutzergruppen'
description: Berechtigungen für viele Benutzer in DefectDojo Pro teilen und pflegen
weight: 3
audience: pro
aliases:
- /en/customize_dojo/user_management/create_user_group
---

> **DefectDojo-Pro-Funktion.** Benutzergruppen und das zugrunde liegende RBAC-System sind Teil von DefectDojo Pro. Open-Source-DefectDojo verwendet das Modell der [Autorisierten Benutzer](../os__authorized_users/) — dort finden Sie Informationen zur Zugriffskontrolle in der Open-Source-Version, sowie die [Hinweise zum 3.0-Upgrade](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization), falls Sie zwischen den Editionen wechseln.

Wenn Sie eine erhebliche Anzahl an DefectDojo-Benutzern haben, möchten Sie möglicherweise eine oder mehrere **Gruppen** erstellen, um für viele Benutzer gleichzeitig dieselben Regeln der rollenbasierten Zugriffskontrolle (RBAC) festzulegen. Nur Superuser können Benutzergruppen erstellen.

Gruppen können auf verschiedene Weise eingesetzt werden:

* Legen Sie eine oder mehrere verschiedene Rollen auf Produkt- oder Produkttyp-Ebene für alle Gruppenmitglieder fest, um genau zu steuern, auf welche Produkte oder Produkttypen die Gruppe zugreifen und welche sie bearbeiten kann.
* Legen Sie eine globale Rolle für alle Gruppenmitglieder fest, die ihnen Einsicht in und Zugriff auf alle Produkte oder Produkttypen gibt.
* Legen Sie Konfigurationsberechtigungen für eine Gruppe fest, die es ihr ermöglichen, bestimmte Funktionen in DefectDojo zu ändern.

Weitere Informationen zu Rollen finden Sie in unserem Artikel **Introduction To Roles**.

## Die Seite „All Groups“

Navigieren Sie in der Seitenleiste zu 👤**Users \> Groups**, um eine Liste aller aktiven und inaktiven Benutzergruppen anzuzeigen.

![Bild](images/Create_a_User_Group_for_shared_permissions.png)
Von hier aus können Sie Ihre einzelnen Gruppenseiten erstellen, löschen oder anzeigen.

Für <span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span>-Benutzer bietet die Seite „All Groups“ der Pro-Benutzeroberfläche einige zusätzliche Optionen.
* Sie können diese Tabelle nach Gruppenname, Beschreibung, E-Mail-Adresse, globaler Rolle sowie der Gesamtzahl der mit der Gruppe verknüpften Benutzer, Produkttypen und Produkte filtern.
* Sie können außerdem die Berechtigungen oder andere Einstellungen einer Gruppe anpassen, indem Sie auf die Schaltfläche „⋮“ neben der zu bearbeitenden Gruppe klicken.

![Bild](images/all_groups_pro.png)

## Eine Gruppe anzeigen

Beim Anzeigen einer Gruppe werden alle Gruppeninformationen angezeigt, etwa ID, Name, Beschreibung, globale Rolle usw. Außerdem werden die Gruppenmitglieder sowie die mit der Gruppe verknüpften Produkttypen und Produkte angezeigt. Zusätzlich können die mit einer Gruppe verbundenen Konfigurationsberechtigungen direkt auf der Seite „View Group“ aktualisiert werden.

Für <span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span>-Benutzer ermöglicht die Gruppenansicht der Pro-Benutzeroberfläche, Anpassungen der Konfigurationsberechtigungen auf leicht abweichende Weise vorzunehmen.

![Bild](images/group_view_pro_ui.png)

* Alle Konfigurationsberechtigungen werden in einem Dropdown-Menü angezeigt, das in Unterkategorien gegliedert ist. Wenn sich die Auswahl der Konfigurationsberechtigungen von ihrem aktuellen Wert unterscheidet, wird eine Schaltfläche „Update Configuration Permissions“ angezeigt.

![Bild](images/groups_pro_configuration_permissions.png)

* Sobald einige zusätzliche Berechtigungen ausgewählt wurden, wird der Benutzer gebeten zu bestätigen, dass er die Berechtigungen für die ausgewählte Gruppe aktualisieren möchte, bevor die Aktualisierung durchgeführt wird.

## Eine Benutzergruppe erstellen/bearbeiten

1. Navigieren Sie in der Seitenleiste zur Seite 👤**Users \> Groups**. Sie sehen eine Liste aller vorhandenen Benutzergruppen, einschließlich ihres Namens, ihrer Beschreibung, der Anzahl der Benutzer, der globalen Rolle (falls zutreffend) und der E-Mail-Adresse.

![Bild](images/Create_a_User_Group_for_shared_permissions_2.png)

2. Klicken Sie auf die Schaltfläche **🛠️** neben der Überschrift „All Groups“ und wählen Sie **+ New Group**.

![Bild](images/Create_a_User_Group_for_shared_permissions_3.png)

3. Dadurch gelangen Sie auf eine Seite, auf der Sie eine neue Gruppe erstellen können. Legen Sie den Namen für diese Gruppe fest und fügen Sie bei Bedarf eine Beschreibung hinzu.

Sie können bei Bedarf auch eine globale Rolle auswählen, die Sie auf diese Gruppe anwenden möchten. Das Hinzufügen einer globalen Rolle zur Gruppe gibt allen Gruppenmitgliedern Zugriff auf alle DefectDojo-Daten, zusammen mit einem begrenzten Bearbeitungszugriff, abhängig von der gewählten globalen Rolle. Weitere Informationen finden Sie in unserem Artikel **Introduction To Roles**.

Das Konto, das eine Gruppe ursprünglich erstellt, erhält standardmäßig die Rolle Owner für diese Gruppe.

### E-Mail-Adresse für den Berichtsversand festlegen

Der Weekly Digest ist ein Bericht über alle der Gruppe zugewiesenen Produkte/Produkttypen. Um einen wöchentlichen Digest versenden zu lassen, geben Sie im Formular zum Erstellen/Bearbeiten der Gruppe die gewünschte Ziel-E-Mail-Adresse ein. Gruppenmitglieder erhalten weiterhin wie gewohnt Benachrichtigungen.

### Eine Gruppenseite anzeigen

Sobald Sie eine Gruppe erstellt haben, können Sie darauf zugreifen, indem Sie sie im Menü unter **Users \> Groups** auswählen.

Die Gruppenseite kann mit einer **Beschreibung** individuell gestaltet werden. Sie enthält eine Liste aller **Gruppenmitglieder** sowie der zugewiesenen **Produkte** und **Produkttypen** und der jeweils zugehörigen **Rolle**.

Hier werden außerdem die **Konfigurationsberechtigungen** der Gruppe aufgeführt.

## Die Benutzer einer Gruppe verwalten

Die Gruppenmitgliedschaft wird auf der jeweiligen Gruppenseite verwaltet, die Sie aus der Liste auf der Seite **Users \> Groups** auswählen können. Klicken Sie auf den hervorgehobenen Gruppennamen, um auf die Gruppenseite zuzugreifen, die Sie bearbeiten möchten.

Um die Mitgliedschaft einer Gruppe anzuzeigen oder zu bearbeiten, muss ein Benutzer über die entsprechenden aktivierten Konfigurationsberechtigungen sowie eine Mitgliedschaft in der Gruppe (oder Superuser-Status) verfügen.

### **Einen Benutzer zu einer Gruppe hinzufügen**

Benutzergruppen können beliebig viele Benutzer zugewiesen bekommen. Alle Benutzer einer Gruppe erhalten die zugehörige Rolle für jedes aufgeführte Produkt oder jeden Produkttyp, Benutzer können jedoch auch individuelle Rollen haben, die die Gruppenrolle überschreiben.

1. Wählen Sie auf der Gruppenseite über die Schaltfläche **☰** am Rand der Überschrift **Members** die Option **+ Add Users**.

![Bild](images/Create_a_User_Group_for_shared_permissions_4.png)

2. Dadurch gelangen Sie zum Bildschirm **Add Some Group Members**. Öffnen Sie das Dropdown-Menü Users und wählen Sie jeden Benutzer aus, den Sie der Gruppe hinzufügen möchten.

![Bild](images/Create_a_User_Group_for_shared_permissions_5.png)

3. Wählen Sie die Gruppenrolle, die Sie diesen Benutzern zuweisen möchten. Diese bestimmt ihre Möglichkeit, die Gruppe zu konfigurieren.

Beachten Sie, dass das Hinzufügen eines Mitglieds zu einer Gruppe ihm standardmäßig keinen Zugriff auf die eigene Gruppenseite gewährt. Dies ist eine separate Konfigurationsberechtigung, die zuerst aktiviert werden muss.

### **Ein Mitglied einer Benutzergruppe bearbeiten oder löschen**

1. Wählen Sie auf der Gruppenseite das ⋮ neben dem Namen des Benutzers, den Sie bearbeiten oder aus der Gruppe löschen möchten.

**📝 Edit** führt Sie zum Bildschirm Edit Member, auf dem Sie die Rolle dieses Benutzers ändern können (von Reader, Maintainer oder Owner zu einer anderen Option).

**🗑️ Delete** entfernt die Mitgliedschaft eines Benutzers vollständig. Beiträge oder Änderungen, die der Benutzer am Produkt oder Produkttyp vorgenommen hat, werden dadurch nicht entfernt.

![Bild](images/Create_a_User_Group_for_shared_permissions_6.png)

## Die Berechtigungen einer Gruppe verwalten

Gruppenberechtigungen werden auf der jeweiligen Gruppenseite verwaltet, die Sie aus der Liste auf der Seite **Users \> Groups** auswählen können. Klicken Sie auf den hervorgehobenen Gruppennamen, um auf die Gruppenseite zuzugreifen, die Sie bearbeiten möchten.

Beachten Sie, dass nur Superuser die Berechtigungen einer Gruppe (Produkt/Produkttyp oder Konfiguration) bearbeiten können.

### **Produktrollen oder Produkttyprollen für eine Gruppe hinzufügen**

Sie können jeder Gruppe beliebig viele Produktrollen oder Produkttyprollen zuweisen.

1. Wählen Sie auf der Gruppenseite unter der entsprechenden Überschrift (Product Type Groups oder Product Groups) **+ Add Product Types** oder **+ Add Product**.

![Bild](images/Create_a_User_Group_for_shared_permissions_7.png)

2. Dadurch gelangen Sie auf die Seite **Register New Products / Product Types**, auf der Sie über das Dropdown-Menü ein Produkt oder einen Produkttyp zum Hinzufügen auswählen können.

![Bild](images/Create_a_User_Group_for_shared_permissions_8.png)

3. Wählen Sie die Rolle aus, die alle Gruppenmitglieder für dieses spezielle Produkt oder diesen Produkttyp haben sollen.

Gruppen können Produkten oder Produkttypen nicht ohne Rolle zugewiesen werden. Wenn Sie nicht sicher sind, welche Rolle eine Gruppe haben soll, ist Reader eine gute „Standard“-Option. So bleibt der Zustand Ihres Produkts sicher, bis Sie sich endgültig für die Gruppenrolle entschieden haben.

### **Konfigurationsberechtigungen einer Gruppe zuweisen**

Wenn die Mitglieder Ihrer Gruppe auf Konfigurationsfunktionen zugreifen und bestimmte Aspekte von DefectDojo steuern können sollen, können Sie diese Verantwortlichkeiten auf der Gruppenseite zuweisen.

Weisen Sie über das Menü in der unteren rechten Ecke die Rechte View, Add, Edit oder Delete zu. Das Aktivieren einer Konfigurationsberechtigung gibt der Gruppe sofort Zugriff auf diese bestimmte Funktion.

![Bild](images/Create_a_User_Group_for_shared_permissions_9.png)
