---
title: Persönliche Benachrichtigungen festlegen
description: Benachrichtigungen für ein persönliches Konto konfigurieren
aliases:
- /en/customize_dojo/notifications/configure_personal_notifs
---

## Persönliche Benachrichtigungen konfigurieren

Persönliche Benachrichtigungen werden zusätzlich zu systemweiten Benachrichtigungen gesendet und gelten für jedes Produkt, jeden Produkttyp und jeden anderen Datentyp, auf den Sie Zugriff haben. Einstellungen für persönliche Benachrichtigungen gelten nur für einen einzelnen Benutzer und können ausschließlich auf dem Konto festgelegt werden, das sie konfiguriert.

![image](images/Configure_System_&_Personal_Notifications.png)

Systembenachrichtigungen werden von einem DefectDojo-Superuser festgelegt; einzelne Benutzer können sie nicht abbestellen.

1. Beginnen Sie auf der Seite „Benachrichtigungen“ (⚙️**Konfiguration \> Benachrichtigungen** in der Seitenleiste).
2. Im Dropdown-Menü **Geltungsbereich** können Sie auswählen, welchen Satz von Benachrichtigungen Sie bearbeiten möchten.
3. Wählen Sie „Persönliche Benachrichtigungen“.
4. Markieren Sie für jeden Benachrichtigungstyp den Zustellweg, den Sie verwenden möchten. Sie können mehrere auswählen.

Persönliche Benachrichtigungen können nicht über Microsoft Teams gesendet werden, da Teams nur globale Benachrichtigungen in einem einzelnen Kanal veröffentlichen kann.

### Persönliche Benachrichtigungen für ein bestimmtes Produkt erhalten

Zusätzlich zu den üblichen persönlichen Benachrichtigungen können DefectDojo-Benutzer auch Benachrichtigungen über Aktivitäten in einem bestimmten Produkt erhalten. Das ist hilfreich, wenn ein Benutzer bestimmte Produkte genauer beobachten muss.

![image](images/Configure_System_&_Personal_Notifications_3.png)

Diese Konfiguration können Sie im Abschnitt **Benachrichtigungen** auf der **Produkt**-Seite ändern, z. B. `your-instance.defectdojo.com/product/{id}`.

Hier können Sie festlegen, ob Sie **🔔 Warnmeldungen**, **Mail**- oder **Slack**-Benachrichtigungen für Aktionen an diesem bestimmten Produkt erhalten möchten. Diese Benachrichtigungen gelten zusätzlich zu allen systemweiten Benachrichtigungen, die Sie bereits erhalten. 

Microsoft Teams kann keinerlei persönliche Benachrichtigungen senden, daher lassen sich Teams-Benachrichtigungen in diesem Menü nicht auswählen.

Persönliche E-Mail-Benachrichtigungen werden immer an die E-Mail-Adresse gesendet, die mit Ihrem DefectDojo-Login verknüpft ist. Informationen zum Einrichten eines persönlichen Slack-Kontos für den Empfang von Benachrichtigungen finden Sie in unserer [Anleitung](../email_slack_teams/#send-personal-notifications-to-slack).