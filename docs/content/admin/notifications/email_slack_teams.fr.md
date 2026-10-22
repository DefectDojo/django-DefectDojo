---
title: Configurer les notifications Email, Slack ou Teams
description: Configurer Microsoft Teams pour recevoir des notifications
aliases:
- /fr/en/customize_dojo/notifications/email_slack_teams
---

**Vous aurez besoin d'un accès Superuser pour utiliser la page System Settings, requise pour effectuer cette procédure.**

Des notifications peuvent être envoyées vers Slack ou Teams lorsque certains événements se déclenchent dans DefectDojo.

## Configuration des notifications Slack

DefectDojo peut publier des notifications Slack de deux manières différentes :

* Des notifications à l'échelle du système, qui seront envoyées à un seul canal Slack
* Des notifications personnelles, qui ne seront envoyées qu'à des utilisateurs spécifiques.

Voici un exemple de notification Slack envoyée depuis DefectDojo :
​
![image](images/Configure_a_Slack_Integration.png)

DefectDojo ne dispose pas d'une application Slack dédiée, mais il est facile d'en créer une pour votre espace de travail en suivant ce guide. Une application Slack est nécessaire pour que les notifications Système et Personnelles soient envoyées correctement.

### Créer une application Slack

Pour configurer une connexion Slack à DefectDojo, vous devrez créer une application Slack personnalisée.

1. Commencez cette procédure depuis la page Slack Apps : <https://api.slack.com/apps>.
2. Cliquez sur '**Create New App**'.
3. Sélectionnez '**From App Manifest**'.
4. Sélectionnez votre espace de travail Slack dans le menu.
5. Saisissez votre App Manifest \- vous pouvez copier\-coller ce fichier JSON, qui inclut tous les paramètres d'autorisation nécessaires au bon fonctionnement de l'intégration Slack.
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

Vérifiez l'App Summary, puis cliquez sur Create App une fois terminé. Terminez l'installation en cliquant sur le bouton **Install To Workplace**.

### Configurer votre intégration Slack dans DefectDojo

Vous devez maintenant configurer l'intégration Slack sur DefectDojo pour terminer l'intégration.

**Vous aurez besoin d'un accès Superuser pour accéder à la page System Settings de DefectDojo.**

1. Accédez à la page App Information de votre application Slack, depuis <https://api.slack.com/apps>. Il s'agit de l'application créée dans la première section \- **Create a Slack application**.
​
2. Trouvez votre OAuth Access Token. Vous le trouverez dans la barre latérale Slack \- **Features / OAuth \& Permissions**. Copiez le **Bot User OAuth Token.
​**

![image](images/Configure_a_Slack_Integration_2.png)

3. Ouvrez DefectDojo dans un nouvel onglet, et accédez à **Configuration \> System Settings** depuis la barre latérale. (Dans l'interface Pro, ce formulaire se trouve sous **Enterprise Settings > System Settings**.)
4. Cochez la case **Enable Slack notifications**.
5. Collez le **Bot User OAuth Token** obtenu à l'étape 1 dans le champ **Slack token**.
6. Le champ **Slack Channel** doit correspondre au canal de votre espace de travail dans lequel vous souhaitez que les notifications soient publiées par un bot DefectDojo.
7. Si vous souhaitez changer le nom du bot DefectDojo, vous pouvez saisir un nom personnalisé ici. Sinon, il utilisera **DefectDojo Notifications**, tel que défini dans le Slack App Manifest.

Une fois cette procédure terminée, DefectDojo peut envoyer des notifications à l'échelle du système vers ce canal. Sélectionnez les notifications que vous souhaitez envoyer depuis la [page System Notifications]().

![image](images/Configure_a_Slack_Integration_3.png)

#### Remarques sur les notifications à l'échelle du système dans Slack\:

Slack ne peut appliquer aucune règle RBAC au canal Slack que vous créez, et partagera donc les notifications pour l'ensemble du système DefectDojo. DefectDojo ne propose aucun moyen de filtrer les notifications Slack à l'échelle du système par Product Type, Produit ou Engagement.

Si vous souhaitez appliquer un filtrage basé sur le RBAC à vos messages Slack, il est préférable d'activer les notifications personnelles depuis Slack.

### Envoyer des notifications personnelles à Slack

Si votre équipe a activé une intégration Slack (via la procédure ci\-dessus), chaque utilisateur peut également configurer des notifications à envoyer directement vers son canal Slackbot personnel.

1. Commencez par accéder à votre page de profil personnelle sur DefectDojo. Vous la trouverez en cliquant sur l'**icône** 👤 en haut à droite. Sélectionnez votre nom d'utilisateur DefectDojo dans la liste. (👤 **paul** dans notre exemple)
​
![image](images/Configure_a_Slack_Integration_4.png)

2. Définissez votre **Slack Email Address** dans le menu. Ce champ se trouve sous **Additional Contact Information** dans DefectDojo.

Vous pouvez maintenant [définir des notifications spécifiques](../about_notifications/) à envoyer vers votre canal Slackbot personnel. Les autres utilisateurs de votre canal Slack ne recevront pas ces messages.

## Configuration des notifications Microsoft Teams

Microsoft Teams peut recevoir des notifications sur un canal spécifique. Pour cela, vous devrez **configurer un webhook entrant** sur le canal où vous souhaitez recevoir les messages.

Notez que les anciens [webhooks Office Connector](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook?tabs=newteams%2Cdotnet) seront retirés par Microsoft ; utilisez un nouveau webhook basé sur un Power Automate Workflow, comme indiqué ci\-dessous.

1. Suivez la procédure décrite dans la **[documentation Microsoft Teams](https://support.microsoft.com/en-us/office/create-incoming-webhooks-with-workflows-for-microsoft-teams-8ae491c7-0394-4861-ba59-055e33f75498)** pour créer un nouveau Incoming Webhook. Gardez votre lien logic.azure.com unique à portée de main, car vous en aurez besoin dans les étapes suivantes. Vous pouvez créer un webhook pour un canal ou pour une discussion spécifique.
​
![image](images/Configure_a_Microsoft_Teams_Integration.png)
2. Dans DefectDojo, accédez à **Configuration \> System Settings** depuis la barre latérale. (Dans l'interface Pro, ce formulaire se trouve sous **Enterprise Settings > System Settings**.)
3. Cochez la case **Enable Microsoft Teams notifications**. Cela ouvrira une section masquée du formulaire, intitulée **'Msteams url**'.
​
![image](images/Configure_a_Microsoft_Teams_Integration_2.png)
4. Collez l'URL logic.azure.com (créée à l'étape 1\) dans le champ **Msteams url**. Votre application Teams écoutera désormais les notifications entrantes de DefectDojo et les publiera dans le canal que vous avez sélectionné.

### Remarques sur l'intégration Teams

* Slack ne peut appliquer aucune règle RBAC au canal Teams que vous créez, et partagera donc les notifications pour l'ensemble du système DefectDojo. DefectDojo ne propose aucun moyen de filtrer les notifications Teams à l'échelle du système par Product Type, Produit ou Engagement.
* DefectDojo ne peut pas envoyer de notifications personnelles aux utilisateurs sur Microsoft Teams.

## Configuration des notifications par e-mail à l'échelle du système

Les notifications de DefectDojo peuvent également être envoyées à une adresse e\-mail spécifique.

1. Depuis la page System Settings (**Configuration > System Settings** dans l'interface Classic, ou **Enterprise Settings > System Settings** dans l'interface Pro) accédez à Enable Mail (email) Notifications.

2. Cochez la case **Enable mail notifications**, puis saisissez l'adresse e\-mail à laquelle vous souhaitez que ces notifications soient envoyées (mail notifications to).

![image](images/notifs_email.png)

Notez que DefectDojo ne peut pas appliquer de filtrage RBAC à ces e\-mails \- ils seront envoyés pour toute l'activité de DefectDojo.  Si vous préférez envoyer un ensemble plus personnalisé de notifications par e\-mail, il est préférable de configurer des [Notifications personnelles](../configure_personal_notifs) avec un utilisateur ou un compte de service lié à l'adresse appropriée.
