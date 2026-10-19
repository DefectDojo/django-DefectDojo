---
title: Berechtigungen in Pro festlegen
description: Überarbeitung, Pro-Funktion
weight: 3
audience: pro
aliases:
- /en/customize_dojo/user_management/pro_permissions_overhaul
---

## Einführung in die Berechtigungstypen

Einzelnen Benutzern können vier verschiedene Arten von Berechtigungen zugewiesen werden:

* Benutzer können als **Mitglieder von Produkten oder Produkttypen** eingetragen werden. Dadurch können sie Datentypen (Produkttypen, Produkte, Engagements, Tests und Befunde) in DefectDojo ansehen und damit arbeiten, abhängig von der Rolle, die ihnen für das jeweilige Produkt zugewiesen ist. Benutzer können mehrere Produkt- oder Produkttyp-Mitgliedschaften mit unterschiedlichen Zugriffsebenen haben.  
​
* Benutzern können außerdem **Konfigurationsberechtigungen** zugewiesen werden, die ihnen Zugriff auf Konfigurationsseiten in DefectDojo geben. Konfigurationsberechtigungen sind nicht mit Produkten oder Produkttypen verknüpft.  
​
* Benutzern können **globale Rollen** zugewiesen werden, die ihnen eine einheitliche Zugriffsebene auf alle Produkte und Produkttypen geben.  
​
* Benutzer können als **Superuser** eingerichtet werden: Rollen auf Administratorebene, die Kontrolle über und Zugriff auf alle Daten und Konfigurationen von DefectDojo geben.

Sie können auch Gruppen erstellen, wenn Sie Produktmitgliedschaften, Konfigurationsberechtigungen oder globale Rollen mehreren Benutzern gleichzeitig zuweisen möchten. Wenn Sie sehr viele Benutzer in DefectDojo haben, etwa ein eigenes Testteam für ein bestimmtes Produkt, sind Gruppen möglicherweise die praktischere Funktion. 

## Superuser \& globale Rollen

Im Rahmen Ihrer Konfiguration der rollenbasierten Zugriffskontrolle (RBAC) kann es erforderlich sein, weitere Superuser oder Benutzer mit globalen Rollen zu erstellen.

* Superuser (Admins) unterliegen keinen Einschränkungen im System. Sie können alle Einstellungen ändern, Benutzer verwalten und haben Lese- und Schreibzugriff auf alle Daten. Sie können außerdem die Zugriffsregeln für alle Benutzer in DefectDojo ändern. Superuser erhalten zudem Benachrichtigungen zu allen Systemproblemen und Warnungen.
* Benutzer mit globalen Rollen können jeden Datentyp (Produkttypen, Produkte, Engagements, Tests und Befunde) in DefectDojo entsprechend ihrer zugewiesenen Rolle ansehen und damit arbeiten. Weitere Informationen zu den einzelnen Rollen und den zugehörigen Rechten finden Sie in unserem Artikel „Einführung in Rollen“.
* Benutzern können außerdem bestimmte Konfigurationsberechtigungen zugewiesen werden, die ihnen Zugriff auf einzelne Konfigurationsseiten von DefectDojo geben. Standardmäßig haben Benutzer keine Konfigurationsberechtigungen.

Standardmäßig verfügt das erste Konto, das auf einer neuen DefectDojo-Instanz erstellt wird, über Superuser-Berechtigungen. Dieser Benutzer kann die Berechtigungen aller weiteren DefectDojo-Benutzer bearbeiten. Nur ein bestehender Superuser kann einen weiteren Superuser anlegen oder einem Benutzer eine globale Rolle zuweisen.

Die Berechtigungen in <span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> wurden vereinfacht, damit sich der Zugriff auf Objekte leichter zuweisen lässt.  Diese Funktion ist über die [Pro-UI](/get_started/about/ui_pro_vs_os/) erreichbar.

### Das Berechtigungsfenster öffnen 

![image](images/pro_permissions.png)

Wenn Sie einen Produkttyp oder ein Produkt betrachten, können Sie das Berechtigungsfenster öffnen, um Berechtigungen schnell festzulegen.  In einer Tabelle finden Sie dieses Menü über die Punkte **„⋮“**.  Auf der Seite eines einzelnen **Produkts** oder **Produkttyps** finden Sie dieses Menü unter dem blauen Zahnrad „⚙️“.

## Berechtigungen über das Berechtigungsfenster festlegen

![image](images/pro_permissions_2.png)

1. Am oberen Rand dieses Fensters können Sie wählen, ob Sie die Berechtigungen für einen einzelnen Benutzer oder für eine [Benutzergruppe](../create_user_group) verwalten möchten.
2. Hier können Sie einen Benutzer oder eine Gruppe auswählen, die dem Produkt hinzugefügt werden soll, und die [Rolle](../about_perms_and_roles) festlegen, die dieser Benutzer haben soll.
3. In der unteren Tabelle sehen Sie eine Liste aller Benutzer und Gruppen, die Zugriff auf dieses Objekt haben.  Über das Dropdown-Menü können Sie einem dieser Benutzer oder einer dieser Gruppen außerdem schnell eine neue Rolle zuweisen.

## Konfigurationsberechtigungen über die Benutzeransicht festlegen

Die Konfigurationsberechtigungen eines Benutzers lassen sich jetzt benutzerfreundlicher festlegen. In der Benutzeransicht werden alle Konfigurationsberechtigungen in einem Dropdown-Menü angezeigt und nach Berechtigungstyp gruppiert. Wenn die Auswahl der Konfigurationsberechtigungen vom aktuellen Wert abweicht, wird die Schaltfläche „Konfigurationsberechtigungen aktualisieren“ angezeigt. Nach dem Klicken wird der Benutzer gebeten zu bestätigen, dass er die Berechtigungen für die ausgewählte Gruppe aktualisieren möchte, bevor die Aktualisierung durchgeführt wird.

![image](images/pro_user_view.png)
