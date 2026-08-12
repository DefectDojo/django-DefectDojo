---
title: Systemweite Benachrichtigungen festlegen
description: So konfigurieren Sie persönliche und Systembenachrichtigungen
aliases:
- /de/en/customize_dojo/notifications/configure_system_notifs
---

DefectDojo verfügt über zwei verschiedene Arten von Benachrichtigungen: **Persönliche** (werden an ein einzelnes Konto gesendet) und **System** (werden an alle Benutzer gesendet).

Sowohl die persönlichen Benachrichtigungen eines Kontos als auch die globalen Systembenachrichtigungen können auf derselben Seite konfiguriert werden: **⚙️Konfiguration \> Benachrichtigungen** in der Seitenleiste.

![image](images/Configure_System_&_Personal_Notifications.png)

## Systembenachrichtigungen konfigurieren (klassische UI)

**Zum Ändern systemweiter Benachrichtigungen benötigen Sie Superuser-Zugriff.**

1. Beginnen Sie auf der Seite „Benachrichtigungen“ (⚙️ **Konfiguration \> Benachrichtigungen** in der Seitenleiste).
2. Im Dropdown-Menü „Geltungsbereich“ wählen Sie aus, welchen Satz von Benachrichtigungen Sie bearbeiten möchten.
3. Wählen Sie „Systembenachrichtigungen“ aus.
4. Aktivieren Sie für jede Art von Benachrichtigung die Zustellmethode, die Sie verwenden möchten. Sie können mehrere auswählen.

![image](images/Configure_System_&_Personal_Notifications_2.png)

Wie Sie Ziele für systemweite E-Mail-Benachrichtigungen (E-Mail, Slack oder MS Teams) festlegen, erfahren Sie in unserer [Anleitung](../email_slack_teams).

## Vorlagen-Benachrichtigungen

Superuser haben außerdem Zugriff auf ein Formular „Vorlage“.  Über das Vorlagen-Formular legen Sie fest, welche persönlichen Benachrichtigungen für neue Benutzer standardmäßig aktiviert sind.

## Wohin Systembenachrichtigungen gesendet werden

Systembenachrichtigungen werden gesendet an:
- die einzelne E-Mail-Adresse, die in den Systemeinstellungen angegeben ist (sofern aktiviert)
- alle DefectDojo-Benutzer mit einem Konto und passenden RBAC-Berechtigungen
- das systemweite Slack- oder Teams-Konto.

Wie jede Benachrichtigung in DefectDojo werden Systembenachrichtigungen nur an Benutzer gesendet, die Zugriff auf die betreffenden Daten haben.  Selbst wenn Produktbenachrichtigungen systemweit eingerichtet sind, erhalten Benutzer also nur Benachrichtigungen zu den Produkten, die sie einsehen dürfen.

Diese Einschränkung gilt nicht für Systembenachrichtigungen, die an eine bestimmte E-Mail-Adresse oder einen bestimmten Slack-Kanal gesendet werden.

Weitere Informationen zu RBAC und zum Festlegen von Berechtigungen finden Sie in unserer Anleitung zur [rollenbasierten Zugriffskontrolle](../../user_management/about_perms_and_roles/).

Die verbundenen System-Konten für E-Mail, Slack und Teams können RBAC jedoch nicht anwenden, da sie keinem bestimmten DefectDojo-Benutzer zugeordnet sind.  **Alle ausgewählten systemweiten Benachrichtigungen werden an diese Ziele gesendet. Sie sollten daher sicherstellen, dass diese Kanäle nur bestimmten Personen in Ihrer Organisation zugänglich sind.**
