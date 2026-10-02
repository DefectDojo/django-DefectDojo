---
title: Massenhaftes Zurücksetzen von Benutzeranmeldedaten
description: API-Tokens rotieren und Passwort-Resets für viele Benutzer gleichzeitig
  über die Benutzerliste erzwingen
audience: pro
weight: 2
---

Die DefectDojo Pro **Benutzer**-Liste ermöglicht es Ihnen, API-Tokens zu rotieren und Passwort-Resets für viele Benutzer gleichzeitig zu erzwingen – nützlich für die regelmäßige Pflege von Anmeldedaten oder als Reaktion auf eine vermutete Kompromittierung von Zugangsdaten.

Diese Massenaktionen stehen nur **Superusern** und Benutzern mit der Rolle **Global Owner** zur Verfügung. Wenn Sie keine dieser Berechtigungen besitzen, werden die Auswahlkästchen und Massenaktions-Schaltflächen nicht angezeigt.

## Benutzer auswählen

Verwenden Sie in der **Benutzer**-Liste die Auswahlkästchen, um einen oder mehrere Benutzer auszuwählen. Es erscheint eine Massenaktionsleiste mit den Reset-Schaltflächen. Jede Aktion fordert Sie vor der Ausführung zur Bestätigung in einem Dialogfeld auf.

Die Aktion gilt für die Benutzer, die Sie explizit ausgewählt haben. Sie **können Ihr eigenes Konto nicht in einen Massen-Reset einbeziehen**: Befindet sich Ihr Konto unter den ausgewählten Zeilen, werden die Massenaktions-Schaltflächen deaktiviert und eine Warnung angezeigt.

## API-Tokens zurücksetzen

**API-Tokens zurücksetzen** rotiert das API-Token jedes ausgewählten Benutzers: DefectDojo löscht das vorhandene Token des Benutzers und stellt ein neues aus. **Das aktuelle Token des Benutzers funktioniert sofort nicht mehr**, daher müssen alle Skripte oder Integrationen, die das alte Token verwenden, mit dem neuen Token aktualisiert werden.

* Die neuen Token-Werte werden Ihnen als Administrator **nicht** angezeigt. Jeder betroffene Benutzer erhält eine Benachrichtigung **„API Token Reset“**, die ihn darüber informiert, sein neues Token über die Benutzeroberfläche abzurufen (Zustellung gemäß den Benachrichtigungseinstellungen dieses Benutzers).

## Passwort-Reset erzwingen

**Passwort-Reset erzwingen** setzt bei jedem ausgewählten Benutzer das Flag *force-password-reset-on-next-login*. Bei der nächsten Anfrage dieses Benutzers leitet DefectDojo ihn auf die Seite **Change Password** um und lässt ihn erst fortfahren, wenn er ein neues Passwort festgelegt hat. Das Flag wird automatisch aufgehoben, sobald dies geschehen ist.

Beachten Sie, was diese Aktion **nicht** tut:

* Sie setzt oder generiert **kein** zufälliges temporäres Passwort und gibt Ihnen **keine** Anmeldedaten zurück.
* Sie sendet den betroffenen Benutzern **keine** E-Mail oder Benachrichtigung. Da es keinen automatischen Hinweis gibt, informieren Sie die betroffenen Benutzer außerhalb des Systems darüber, dass sie beim nächsten Login zur Passwortänderung aufgefordert werden.

> **SSO-Benutzer:** Anders als das Bearbeitungsformular für einzelne Benutzer (das das Force-Reset-Flag für SSO-autorisierte Konten deaktiviert), wendet die Massenaktion das Flag auf **jeden** ausgewählten Benutzer an, unabhängig davon, wie er sich authentifiziert. Da sich SSO-Benutzer über Ihren Identity Provider anmelden und nicht über ein DefectDojo-Passwort, ist ein erzwungener Passwort-Reset bei ihnen in der Regel nicht sinnvoll – vermeiden Sie es, reine SSO-Benutzer in die Auswahl einzubeziehen.
