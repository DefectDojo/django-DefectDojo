---
title: Open-Source-Berechtigungen
description: Wie der Zugriff auf Produkte und Produkttypen im Open-Source-DefectDojo
  gewährt wird
weight: 1
audience: opensource
---

Open-Source-DefectDojo steuert den Zugriff auf Produkte und Produkttypen über das Modell **Authorized Users**. Jedes Produkt und jeder Produkttyp verfügt über ein Authorized-Users-Panel, das die Personen auflistet, die diesen Datensatz und die darunter verschachtelten Daten sehen können.

Wenn Sie DefectDojo Pro einsetzen, gilt dieser Artikel nicht für Ihre Installation – Pro verwendet ein umfangreicheres rollenbasiertes System, das in [Berechtigungen in DefectDojo](../about_perms_and_roles/) beschrieben wird.

## Wie der Zugriff gewährt wird

Es gibt zwei Listen, und ein Benutzer muss nur auf einer davon stehen, um Zugriff zu erhalten:

- **Die Authorized-Users-Liste eines Produkts** gewährt Zugriff auf dieses eine Produkt sowie auf alles, was darunter verschachtelt ist (dessen Engagements, Tests, Befunde und Endpunkte).
- **Die Authorized-Users-Liste eines Produkttyps** gewährt Zugriff auf den Produkttyp selbst **und wirkt sich kaskadierend auf jedes darunterliegende Produkt aus**. Ein Benutzer, der für einen Produkttyp autorisiert ist, muss nicht zusätzlich zu jedem untergeordneten Produkt hinzugefügt werden – er ist bereits abgedeckt.

Es gibt keine Rollen, keine Gruppen und keine globalen Rollen. Ein Benutzer steht entweder auf der Liste (oder ist Superuser/Staff-Mitglied – siehe unten), oder er kann das Produkt nicht sehen.

## Superuser und Staff umgehen die Listen

Benutzer, die in DefectDojo als **Superuser** oder **Staff** markiert sind, können unabhängig von den Authorized-Users-Listen jedes Produkt und jeden Produkttyp sehen und bearbeiten. Die Listen dienen dazu, Nicht-Staff-Benutzern Zugriff zu gewähren; sie schränken Staff-Mitglieder oder Superuser nicht ein.

Das erste Konto, das auf einer neuen DefectDojo-Installation erstellt wird, ist automatisch ein Superuser.

## Wer die Listen bearbeiten kann

Nur **Superuser** oder **Staff**-Benutzer sehen die Bedienelemente, um Personen zu einem Authorized-Users-Panel hinzuzufügen oder daraus zu entfernen. Alle anderen, die Zugriff auf ein Produkt oder einen Produkttyp haben, sehen das Panel als schreibgeschützte Übersicht – nützlich, um herauszufinden, wer sonst noch im Team ist, aber nicht, um die Mitgliedschaft zu ändern.

## Wo sich das Panel befindet

Das Authorized-Users-Panel erscheint auf zwei Seiten der klassischen Benutzeroberfläche:

- Die **Produktdetailseite** verfügt über ein Authorized-Users-Panel für dieses Produkt. Sie unterstützt zwei Aktionen für Staff-Benutzer:
  - **Einen Benutzer zur Authorized-Users-Liste des Produkts hinzufügen**
  - **Einen Benutzer aus der Authorized-Users-Liste des Produkts entfernen**
- Die **Produkttyp-Detailseite** verfügt über ein Authorized-Users-Panel für diesen Produkttyp, mit den entsprechenden zwei Aktionen:
  - **Einen Benutzer zur Authorized-Users-Liste des Produkttyps hinzufügen**
  - **Einen Benutzer aus der Authorized-Users-Liste des Produkttyps entfernen**

Wenn Sie einen Benutzer von der Liste eines Produkttyps entfernen, entfällt auch die Kaskade – er verliert den Zugriff auf jedes untergeordnete Produkt, sofern er nicht weiterhin auf der Liste eines bestimmten Produkts steht oder Staff-Mitglied/Superuser ist.

## Entscheidung zwischen Produkt- und Produkttyp-Zugriff

Ein paar Faustregeln:

- Wenn eine Person jedes Produkt unter einer Kategorie sehen soll (zum Beispiel jedes Produkt, das einem bestimmten Team gehört), fügen Sie sie zur Liste des **Produkttyps** hinzu und überlassen Sie den Rest der Kaskade.
- Wenn eine Person nur ein bestimmtes Produkt sehen soll, fügen Sie sie zur Liste dieses **Produkts** hinzu.
- Wenn Sie dieselbe Person zu vielen einzelnen Produkten unter einem Produkttyp hinzufügen, ist das ein Zeichen dafür, dass Sie sie stattdessen zum Produkttyp hinzufügen sollten.

## Umstieg von einer früheren DefectDojo-Version

DefectDojo Open Source ist in Version 3.0 zum Authorized-Users-Modell zurückgekehrt. Wenn Sie von einer Version aktualisieren, die das System Members / Groups / Global Roles verwendet hat, wird Ihr bestehender Zugriff durch das Upgrade automatisch in Authorized Users übernommen – eine manuelle Zuordnung ist nicht erforderlich.

Das Upgrade wird mit einem schreibgeschützten Management-Command, `preview_legacy_authorization_migration`, ausgeliefert, der anhand einer Kopie Ihrer Datenbank zusammenfasst, was ein Upgrade ändern würde. Der empfohlene Ablauf ist, 3.0 in einer Staging-Umgebung mit einem Snapshot der Produktionsumgebung zu installieren, den Befehl auszuführen, die Zusammenfassung zu prüfen und erst dann die Produktionsumgebung zu aktualisieren.

Wenn Sie sich in die andere Richtung bewegen – von Open Source zu DefectDojo Pro –, liefert Pro einen Befehl `reconcile_authorized_users_to_rbac`, der den Authorized-Users-Zugriff in das RBAC von Pro übernimmt. Er unterstützt `--dry-run` und ist idempotent.

Weitere Details zu beiden Wegen finden Sie in den [Upgrade-Hinweisen zu 3.0](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization).
