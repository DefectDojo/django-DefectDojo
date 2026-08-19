---
title: Configurare le notifiche Email, Slack o Teams
description: Configura Microsoft Teams per ricevere le notifiche
aliases:
- /it/en/customize_dojo/notifications/email_slack_teams
---

**Sarà necessario l'accesso Superuser per utilizzare la pagina System Settings, indispensabile per completare questa procedura.**

Le notifiche possono essere inviate a Slack o Teams quando in DefectDojo si verificano determinati eventi.

## Configurazione delle notifiche Slack

DefectDojo può pubblicare notifiche su Slack in due modi diversi:

* Notifiche a livello di sistema, che verranno inviate a un singolo canale Slack
* Notifiche personali, che verranno inviate solo a utenti specifici.

Ecco un esempio di notifica Slack inviata da DefectDojo:
​
![image](images/Configure_a_Slack_Integration.png)

DefectDojo non dispone di un'app Slack dedicata, ma è possibile crearne facilmente una per il proprio workspace seguendo questa guida. Un'app Slack è necessaria per l'invio corretto sia delle notifiche di sistema sia di quelle personali.

### Creare un'applicazione Slack

Per configurare una connessione Slack con DefectDojo, è necessario creare un'app Slack personalizzata.

1. Avviare questa procedura dalla pagina Slack Apps: <https://api.slack.com/apps>.
2. Fare clic su ‘**Create New App**’.
3. Selezionare ‘**From App Manifest**’.
4. Selezionare il proprio workspace Slack dal menu.
5. Inserire il proprio App Manifest \- è possibile copiare e incollare questo file JSON, che include tutte le impostazioni dei permessi necessarie per consentire il funzionamento dell'integrazione Slack.
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

Rivedere l'App Summary e fare clic su Create App al termine. Completare l'installazione facendo clic sul pulsante **Install To Workplace**.

### Configurare l'integrazione Slack in DefectDojo

A questo punto è necessario configurare l'integrazione Slack su DefectDojo per completare l'integrazione.

**Sarà necessario l'accesso Superuser per accedere alla pagina System Settings di DefectDojo.**

1. Accedere alla pagina App Information della propria app Slack da <https://api.slack.com/apps>. Si tratta dell'app creata nella prima sezione \- **Creare un'applicazione Slack**.
​

2. Individuare il proprio OAuth Access Token, reperibile nella barra laterale di Slack in **Features / OAuth \& Permissions**. Copiare il **Bot User OAuth Token.
​**

![image](images/Configure_a_Slack_Integration_2.png)

3. Aprire DefectDojo in una nuova scheda e accedere a **Configuration \> System Settings** dalla barra laterale. (Nella UI Pro, questo modulo si trova in **Enterprise Settings > System Settings**.)
4. Selezionare la casella **Enable Slack notifications**.
5. Incollare il **Bot User OAuth Token** ottenuto al passaggio 1 nel campo **Slack token**.
6. Il campo **Slack Channel** deve corrispondere al canale del workspace in cui si desidera che il bot di DefectDojo scriva le notifiche.
7. Per modificare il nome del bot di DefectDojo, è possibile inserire qui un nome personalizzato. In caso contrario, verrà utilizzato **DefectDojo Notifications**, come definito nell'App Manifest di Slack.

Una volta completata questa procedura, DefectDojo può inviare notifiche a livello di sistema a questo canale. Selezionare le notifiche che si desidera inviare dalla [pagina System Notifications]().

![image](images/Configure_a_Slack_Integration_3.png)

#### Note sulle notifiche a livello di sistema in Slack:

Slack non può applicare alcuna regola RBAC al canale Slack che si sta creando, e quindi condividerà le notifiche per l'intero sistema DefectDojo. In DefectDojo non esiste alcun metodo per filtrare le notifiche Slack a livello di sistema per Product Type, Prodotto o Engagement.

Per applicare un filtraggio basato su RBAC ai propri messaggi Slack, è preferibile abilitare le notifiche personali di Slack.

### Inviare notifiche personali a Slack

Se il proprio team ha abilitato un'integrazione Slack (tramite la procedura sopra descritta), i singoli utenti possono anche configurare le notifiche da inviare direttamente al proprio canale Slackbot personale.

1. Iniziare accedendo alla propria pagina Profile personale su DefectDojo. È possibile trovarla facendo clic sull'**icona** 👤 nell'angolo in alto a destra. Selezionare il proprio Username di DefectDojo dall'elenco. (👤 **paul** nel nostro esempio)
​

![image](images/Configure_a_Slack_Integration_4.png)

2. Impostare il proprio **Slack Email Address** nel menu. Questo campo si trova all'interno di **Additional Contact Information** in DefectDojo.

A questo punto è possibile [impostare notifiche specifiche](../about_notifications/) da inviare al proprio canale Slackbot personale. Gli altri utenti del canale Slack non riceveranno questi messaggi.

## Configurazione delle notifiche Microsoft Teams

Microsoft Teams può ricevere notifiche su un canale specifico. Per farlo, è necessario **configurare un incoming webhook** sul canale in cui si desidera ricevere i messaggi.

Da notare che i vecchi [webhook Office Connector](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook?tabs=newteams%2Cdotnet) verranno dismessi da Microsoft: utilizzare un nuovo webhook basato su Power Automate Workflow, come descritto di seguito.

1. Completare la procedura descritta nella **[documentazione Microsoft Teams](https://support.microsoft.com/en-us/office/create-incoming-webhooks-with-workflows-for-microsoft-teams-8ae491c7-0394-4861-ba59-055e33f75498)** per creare un nuovo Incoming Webhook. Tenere a portata di mano il proprio link univoco logic.azure.com, poiché servirà nei passaggi successivi. È possibile creare un webhook per un canale o per una chat specifica.
​
![image](images/Configure_a_Microsoft_Teams_Integration.png)
2. In DefectDojo, accedere a **Configuration \> System Settings** dalla barra laterale. (Nella UI Pro, questo modulo si trova in **Enterprise Settings > System Settings**.)
3. Selezionare la casella **Enable Microsoft Teams notifications**. Questo aprirà una sezione nascosta del modulo, denominata ‘**Msteams url**’.
​
![image](images/Configure_a_Microsoft_Teams_Integration_2.png)
4. Incollare l'URL logic.azure.com (creato al passaggio 1\) nel campo **Msteams url**. L'app Teams sarà ora in ascolto delle notifiche in arrivo da DefectDojo e le pubblicherà nel canale selezionato.

### Note sull'integrazione con Teams

* Slack non può applicare alcuna regola RBAC al canale Teams che si sta creando, e quindi condividerà le notifiche per l'intero sistema DefectDojo. In DefectDojo non esiste alcun metodo per filtrare le notifiche Teams a livello di sistema per Product Type, Prodotto o Engagement.
* DefectDojo non può inviare notifiche personali agli utenti su Microsoft Teams.

## Configurazione delle notifiche email a livello di sistema

Le notifiche di DefectDojo possono anche essere inviate a un indirizzo email specifico.

1. Dalla pagina System Settings (**Configuration > System Settings** nella UI Classic, oppure **Enterprise Settings > System Settings** nella UI Pro) accedere a Enable Mail (email) Notifications.

2. Selezionare la casella **Enable mail notifications**, quindi inserire l'indirizzo email a cui inviare queste notifiche (mail notifications to).

![image](images/notifs_email.png)

Da notare che DefectDojo non può applicare un filtraggio RBAC a queste email - verranno inviate per tutte le attività in DefectDojo.  Se si preferisce inviare un insieme più personalizzato di notifiche email, è meglio configurare le [notifiche personali](../configure_personal_notifs) con un utente o un account di servizio collegato all'indirizzo appropriato.
