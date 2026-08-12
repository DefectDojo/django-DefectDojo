---
title: E-Mail-, Slack- oder Teams-Benachrichtigungen einrichten
description: Microsoft Teams für den Empfang von Benachrichtigungen einrichten
aliases:
- /en/customize_dojo/notifications/email_slack_teams
---

**Für die Seite „Systemeinstellungen“, die für diesen Vorgang erforderlich ist, benötigen Sie Superuser-Zugriff.**

Benachrichtigungen können an Slack oder Teams gesendet werden, wenn in DefectDojo bestimmte Ereignisse ausgelöst werden.

## Slack-Benachrichtigungen einrichten

DefectDojo kann Slack-Benachrichtigungen auf zwei verschiedene Arten senden: 

* Systemweite Benachrichtigungen, die an einen einzelnen Slack-Kanal gesendet werden
* Persönliche Benachrichtigungen, die nur an bestimmte Benutzer gesendet werden.

Hier ein Beispiel für eine Slack-Benachrichtigung aus DefectDojo:  
​
![image](images/Configure_a_Slack_Integration.png)

DefectDojo hat keine eigene Slack-App, aber Sie können mit dieser Anleitung ganz einfach eine für Ihren Workspace erstellen. Eine Slack-App ist erforderlich, damit sowohl System- als auch persönliche Benachrichtigungen korrekt gesendet werden.

### Eine Slack-App erstellen

Um eine Slack-Verbindung zu DefectDojo einzurichten, müssen Sie eine eigene Slack-App erstellen.

1. Beginnen Sie auf der Seite mit den Slack-Apps: <https://api.slack.com/apps>.
2. Klicken Sie auf ‘**Create New App**’.
3. Wählen Sie ‘**From App Manifest**’.
4. Wählen Sie Ihren Slack-Workspace aus dem Menü aus.
5. Geben Sie Ihr App-Manifest ein \- Sie können diese JSON-Datei kopieren und einfügen; sie enthält alle Berechtigungseinstellungen, die für den Betrieb der Slack-Integration erforderlich sind.  
​
```
{  
   "_metadata": {  
     "major_version": 1,  
     "minor_version": 1  
   },  
   "display_information": {  
     "name": "DefectDojo",  
     "description": "Notifications from DefectDojo. See https://docs.defectdojo.com/en/notifications/configure-a-slack-integration/ for configuration steps.",  
     "background_color": "#0000AA"  
   },  
   "features": {  
       "bot_user": {  
           "display_name": "DefectDojo Notifications"  
       }  
   },  
   "oauth_config": {  
     "scopes": {  
       "bot": [  
         "chat:write",  
         "chat:write.customize",  
         "chat:write.public",  
         "incoming-webhook",  
         "users:read",  
         "users:read.email"  
       ]  
     },  
     "redirect_urls": [  
       "https://slack.com/oauth/v2/authorize"  
     ]  
   }  
 }
```

Prüfen Sie die App-Zusammenfassung und klicken Sie anschließend auf „Create App“. Schließen Sie die Installation über die Schaltfläche **Install To Workplace** ab.

### Slack-Integration in DefectDojo konfigurieren

Jetzt müssen Sie die Slack-Integration in DefectDojo konfigurieren, um die Einrichtung abzuschließen.

**Für den Zugriff auf die Seite „Systemeinstellungen“ von DefectDojo benötigen Sie Superuser-Zugriff.**

1. Öffnen Sie über <https://api.slack.com/apps> die Seite „App Information“ Ihrer Slack-App. Das ist die App, die im ersten Abschnitt \- **Eine Slack-App erstellen** \- erstellt wurde.  
​
2. Suchen Sie Ihr OAuth Access Token. Sie finden es in der Slack-Seitenleiste \- **Features / OAuth \& Permissions**. Kopieren Sie das **Bot User OAuth Token.  
​**

![image](images/Configure_a_Slack_Integration_2.png)

3. Öffnen Sie DefectDojo in einem neuen Tab und navigieren Sie in der Seitenleiste zu **Konfiguration \> Systemeinstellungen**. (In der Pro-UI finden Sie dieses Formular unter **Enterprise-Einstellungen > Systemeinstellungen**.)
4. Aktivieren Sie das Kontrollkästchen **Slack-Benachrichtigungen aktivieren**.
5. Fügen Sie das **Bot User OAuth Token** aus Schritt 1 in das Feld **Slack token** ein.
6. Das Feld **Slack Channel** muss dem Kanal in Ihrem Workspace entsprechen, in dem ein DefectDojo-Bot Ihre Benachrichtigungen schreiben soll.
7. Wenn Sie den Namen des DefectDojo-Bots ändern möchten, können Sie hier einen eigenen Namen eingeben. Andernfalls wird **DefectDojo Notifications** verwendet, wie im Slack-App-Manifest festgelegt.

Sobald dieser Vorgang abgeschlossen ist, kann DefectDojo systemweite Benachrichtigungen an diesen Kanal senden. Wählen Sie auf der [Seite für Systembenachrichtigungen]() die Benachrichtigungen aus, die gesendet werden sollen.

![image](images/Configure_a_Slack_Integration_3.png)

#### Hinweise zu systemweiten Benachrichtigungen in Slack:

Slack kann auf den von Ihnen erstellten Slack-Kanal keine RBAC-Regeln anwenden. Dort werden daher Benachrichtigungen für das gesamte DefectDojo-System geteilt. In DefectDojo gibt es keine Möglichkeit, systemweite Slack-Benachrichtigungen nach Produkttyp, Produkt oder Engagement zu filtern.

Wenn Sie Ihre Slack-Nachrichten anhand von RBAC filtern möchten, ist es besser, persönliche Benachrichtigungen für Slack zu aktivieren.

### Persönliche Benachrichtigungen an Slack senden

Wenn in Ihrem Team eine Slack-Integration aktiviert ist (über den oben beschriebenen Vorgang), können einzelne Benutzer Benachrichtigungen auch direkt an ihren persönlichen Slackbot-Kanal senden lassen.

1. Navigieren Sie zunächst zu Ihrer persönlichen Profilseite in DefectDojo. Sie finden sie über das 👤 **Symbol** in der rechten oberen Ecke. Wählen Sie Ihren DefectDojo-Benutzernamen aus der Liste aus. (👤 **paul** in unserem Beispiel)
​
![image](images/Configure_a_Slack_Integration_4.png)

2. Legen Sie im Menü Ihre **Slack-E-Mail-Adresse** fest. Dieses Feld befindet sich in DefectDojo unter **Additional Contact Information**.

Sie können nun [bestimmte Benachrichtigungen](../about_notifications/) an Ihren persönlichen Slackbot-Kanal senden lassen. Andere Benutzer in Ihrem Slack-Kanal erhalten diese Nachrichten nicht.

## Microsoft Teams-Benachrichtigungen einrichten

Microsoft Teams kann Benachrichtigungen in einem bestimmten Kanal empfangen. Dazu müssen Sie in dem Kanal, in dem Sie Nachrichten empfangen möchten, **einen eingehenden Webhook einrichten**.

Bitte beachten Sie, dass die alten [Office-Connector-Webhooks](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook?tabs=newteams%2Cdotnet) von Microsoft abgeschaltet werden. Verwenden Sie stattdessen einen neuen Webhook auf Basis von Power Automate Workflows, wie unten beschrieben.

1. Führen Sie den in der **[Microsoft Teams-Dokumentation](https://support.microsoft.com/en-us/office/create-incoming-webhooks-with-workflows-for-microsoft-teams-8ae491c7-0394-4861-ba59-055e33f75498)** beschriebenen Vorgang zum Erstellen eines neuen eingehenden Webhooks aus. Halten Sie Ihren eindeutigen logic.azure.com-Link bereit, da Sie ihn in den nächsten Schritten benötigen. Sie können den Webhook für einen Kanal oder für einen bestimmten Chat erstellen.
​
![image](images/Configure_a_Microsoft_Teams_Integration.png)
2. Navigieren Sie in DefectDojo in der Seitenleiste zu **Konfiguration \> Systemeinstellungen**. (In der Pro-UI finden Sie dieses Formular unter **Enterprise-Einstellungen > Systemeinstellungen**.)
3. Aktivieren Sie das Kontrollkästchen **Microsoft Teams-Benachrichtigungen aktivieren**. Dadurch wird ein verborgener Abschnitt des Formulars mit der Bezeichnung **‘Msteams url**’ eingeblendet.
​
![image](images/Configure_a_Microsoft_Teams_Integration_2.png)
4. Fügen Sie die in Schritt 1\) erstellte logic.azure.com-URL in das Feld **Msteams url** ein. Ihre Teams-App wartet nun auf eingehende Benachrichtigungen von DefectDojo und veröffentlicht sie in dem von Ihnen ausgewählten Kanal.

### Hinweise zur Teams-Integration

* Slack kann auf den von Ihnen erstellten Teams-Kanal keine RBAC-Regeln anwenden. Dort werden daher Benachrichtigungen für das gesamte DefectDojo-System geteilt. In DefectDojo gibt es keine Möglichkeit, systemweite Teams-Benachrichtigungen nach Produkttyp, Produkt oder Engagement zu filtern.
* DefectDojo kann keine persönlichen Benachrichtigungen an Benutzer in Microsoft Teams senden.

## Systemweite E-Mail-Benachrichtigungen einrichten

Benachrichtigungen aus DefectDojo können auch an eine bestimmte E-Mail-Adresse gesendet werden.

1. Navigieren Sie auf der Seite „Systemeinstellungen“ (**Konfiguration > Systemeinstellungen** in der klassischen UI bzw. **Enterprise-Einstellungen > Systemeinstellungen** in der Pro-UI) zum Abschnitt für E-Mail-Benachrichtigungen. 

2. Aktivieren Sie das Kontrollkästchen **E-Mail-Benachrichtigungen aktivieren** und geben Sie dann die E-Mail-Adresse ein, an die diese Benachrichtigungen gesendet werden sollen (mail notifications to).

![image](images/notifs_email.png)

Beachten Sie, dass DefectDojo auf diese E-Mails keine RBAC-Filterung anwenden kann - sie werden für alle Aktivitäten in DefectDojo gesendet.  Wenn Sie einen stärker angepassten Satz von E-Mail-Benachrichtigungen versenden möchten, richten Sie besser [persönliche Benachrichtigungen](../configure_personal_notifs) mit einem Benutzer- oder Servicekonto ein, das mit der passenden Adresse verknüpft ist.

