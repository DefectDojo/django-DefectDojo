---
title: Connecteurs de messagerie
description: Envoyez des alertes de DefectDojo vers Slack, Microsoft Teams, un e-mail
  ou Amazon SNS.
weight: 4
audience: pro
---

**Disponibilité :** les connecteurs de messagerie sont une fonctionnalité bêta. Activez **Messaging Connectors** sur la page Feature Flags. Comme les alertes sont acheminées par des règles, **Rules Engine 2.0** doit également être activé.

Les connecteurs de messagerie envoient des alertes de DefectDojo vers un service de chat, une adresse e-mail ou un topic Amazon SNS. Ils se trouvent à côté des connecteurs de ticketing et de gestion des incidents sur la même page **Downstream Connectors**, et se configurent de la même manière : créez une connexion une fois, puis décidez ce qui doit lui être envoyé.

Les connecteurs de ticketing et les connecteurs de messagerie répondent à des questions différentes. Un connecteur de ticketing crée et met à jour un ticket qui suit une Constatation dans le temps. Un connecteur de messagerie publie un message à propos de quelque chose qui vient de se produire, par exemple un import ayant apporté de nouvelles Constatations de sévérité Élevée et Critique. Un message n'a pas de statut à faire évoluer ni de ticket à synchroniser, les deux sont donc configurés séparément et n'ont aucun effet l'un sur l'autre.

## Ce que vous pouvez envoyer

Les alertes sont acheminées par Rules Engine 2.0. Une règle détermine **quand** envoyer (un déclencheur), **quelles** Constatations sont éligibles (des conditions), et **où** le message est envoyé (un nœud de notification indiquant votre connexion et votre canal).

Cela signifie que les filtres disponibles pour une alerte sont les mêmes que ceux disponibles pour une règle : sévérité, périmètre, étiquettes, statut, et tout ce qu'une condition de règle peut exprimer. Plusieurs alertes différentes allant vers plusieurs canaux différents ne sont donc que plusieurs règles.

## Les quatre fournisseurs

| Vendor | What you provide | How many destinations per connection |
| --- | --- | --- |
| Slack | Un jeton de bot d'une application Slack | Plusieurs. Chaque destination désigne un ID de canal. |
| Microsoft Teams | Une URL de workflow Power Automate | Une seule. L'URL détermine le canal. |
| Email | Rien. Le serveur de messagerie de l'instance est utilisé. | Plusieurs. Chaque destination désigne des destinataires. |
| Amazon SNS | Une clé d'accès AWS autorisée à publier | Plusieurs. Chaque destination désigne un ARN de topic. |

Chacun se configure de la même manière : ajoutez la connexion sous **Connect > Downstream**, puis créez une alerte
qui l'utilise.

## Configurer une connexion Slack

Vous avez besoin d'une application Slack avec un jeton de bot. Si votre espace de travail en possède déjà une pour DefectDojo, vous pouvez la réutiliser.

### 1. Créer une application Slack

1. Rendez-vous sur [https://api.slack.com/apps](https://api.slack.com/apps) et sélectionnez **Create New App**, puis **From scratch**.
2. Nommez l'application (par exemple, DefectDojo) et choisissez l'espace de travail sur lequel elle doit publier.
3. Ouvrez **OAuth & Permissions** et ajoutez ces **Bot Token Scopes** :
   - `chat:write` (obligatoire) : permet à l'application de publier des messages.
   - `chat:write.public` (facultatif) : permet à l'application de publier dans n'importe quel canal public sans y être invitée au préalable. Sans cette portée, vous devez inviter le bot dans chaque canal que vous souhaitez utiliser.
4. Sélectionnez **Install to Workspace** et approuvez l'application.
5. Copiez le **Bot User OAuth Token**. Il commence par `xoxb-`.

### 2. Ajouter la connexion dans DefectDojo

1. Allez dans **Connect > Downstream**.
2. Dans la section **Messaging**, trouvez la vignette Slack et sélectionnez **Add Configuration**.
3. Renseignez :
   - **Location** : l'URL de votre espace de travail Slack, par exemple `https://your-workspace.slack.com`. Elle sert uniquement à l'affichage et aux liens.
   - **Identifier** : un libellé qui distingue cette connexion des autres, par exemple `Security workspace`.
   - **Bot Token** : le jeton `xoxb-` que vous avez copié.
4. Enregistrez. DefectDojo valide immédiatement le jeton auprès de Slack, de sorte qu'un jeton incorrect ou révoqué est signalé ici plutôt qu'au premier déclenchement d'une alerte.

Vous pouvez ajouter autant de connexions Slack que nécessaire. Des connexions distinctes permettent d'atteindre plusieurs espaces de travail.

### 3. Trouver l'ID du canal

Les destinations Slack utilisent un **ID** de canal, et non un nom de canal.

1. Dans Slack, ouvrez le canal et sélectionnez son nom en haut.
2. Faites défiler jusqu'en bas de l'onglet **About**.
3. Copiez le **Channel ID**. Il ressemble à `C0123456789`.

Si l'application ne dispose pas de la portée `chat:write.public`, invitez-la également dans le canal : saisissez `/invite @your-app-name` dans le canal.

## Configurer une connexion Microsoft Teams

Teams utilise une **URL de workflow Power Automate**. Les connecteurs Office 365 classiques sont retirés, et cette méthode
ne nécessite ni enregistrement d'application ni consentement d'administrateur du tenant : une personne disposant des droits sur le canal
crée le flux et colle l'URL qu'il retourne.

**Une connexion publie sur un seul canal.** L'URL du workflow détermine où le message est envoyé, donc un
second canal nécessite une seconde connexion plutôt qu'une seconde destination.

### 1. Créer le workflow

1. Dans Teams, ouvrez le canal sur lequel vous voulez publier, sélectionnez le menu **...** à côté du nom du canal, puis **Workflows**.
2. Choisissez le modèle **Post to a channel when a webhook request is received**.
3. Confirmez l'équipe et le canal, puis sélectionnez **Add workflow**.
4. Copiez l'URL fournie par le workflow. C'est une longue adresse `https://` sur un hôte Microsoft Power Automate.

Traitez cette URL comme un mot de passe. Quiconque la détient peut publier dans ce canal.

### 2. Ajouter la connexion dans DefectDojo

1. Allez dans **Connect > Downstream**.
2. Dans la section **Messaging**, trouvez la vignette Microsoft Teams et sélectionnez **Add Configuration**.
3. Renseignez :
   - **Location** : votre URL Teams ou Microsoft 365. Elle sert uniquement à l'affichage et aux liens.
   - **Instance Label** : un libellé nommant le canal atteint par cette connexion, par exemple `Security / Alerts`.
   - **Workflow URL** : l'URL que vous avez copiée.
4. Enregistrez.

DefectDojo vérifie la forme de l'URL à l'enregistrement (elle doit être en `https://` et sur un hôte de workflow Microsoft) mais ne publie rien dessus. Une URL de workflow ne peut être testée qu'en envoyant un message, et un message surprise dans un canal au moment de l'enregistrement serait pire que de le découvrir plus tard. Utilisez **Send test message** quand vous êtes prêt.

Une destination Teams comporte un champ optionnel, un libellé de canal, qui ne fait qu'étiqueter l'enregistrement de livraison. L'URL du workflow détermine déjà la destination.

## Configurer une connexion E-mail

L'e-mail ne nécessite aucun identifiant. DefectDojo envoie via le serveur de messagerie que cette instance utilise déjà pour les notifications, il n'y a donc rien de nouveau à configurer et pas de second endroit où le SMTP pourrait être mal réglé.

1. Allez dans **Connect > Downstream**.
2. Dans la section **Messaging**, trouvez la vignette Email et sélectionnez **Add Configuration**.
3. Renseignez :
   - **Location** : l'identité de l'expéditeur à afficher, par exemple `mailto:defectdojo@example.com`.
   - **Instance Label** : un libellé qui distingue cette connexion des autres.
4. Enregistrez.

L'enregistrement échoue si cette instance n'a ni serveur de messagerie ni adresse d'expéditeur configurés, car rien de ce qui est envoyé via la connexion ne quitterait le bâtiment. Configurez d'abord le SMTP sous **Settings > System Settings**.

Les destinataires sont définis sur l'alerte, et non sur la connexion, si bien qu'une seule connexion E-mail sert toutes les alertes. Une destination e-mail accepte jusqu'à 50 adresses ; au-delà, utilisez une adresse de diffusion.

## Configurer une connexion Amazon SNS

SNS est d'une nature différente des trois autres : DefectDojo publie un message vers un topic, et AWS
le diffuse à tout ce qui y est abonné, qu'il s'agisse d'adresses e-mail, de numéros SMS, d'une fonction Lambda,
d'un point de terminaison HTTPS, ou d'une file SQS. DefectDojo ne sait pas et ne se préoccupe pas de savoir lequel.

### 1. Créer une clé d'accès pouvant publier

1. Dans la console AWS, créez (ou choisissez) un utilisateur ou un rôle IAM pour DefectDojo.
2. Attachez une politique autorisant `sns:Publish` sur les topics que vous comptez utiliser. Nommer explicitement les ARN de topics vaut mieux que de tous les autoriser.
3. Créez une clé d'accès pour cet utilisateur et copiez les deux parties. AWS n'affiche la clé d'accès secrète qu'une seule fois.

Si le topic est chiffré avec une clé KMS, le même principal a également besoin de `kms:GenerateDataKey` et `kms:Decrypt` sur cette clé, sinon chaque publication est refusée.

### 2. Ajouter la connexion dans DefectDojo

1. Allez dans **Connect > Downstream**.
2. Dans la section **Messaging**, trouvez la vignette Amazon SNS et sélectionnez **Add Configuration**.
3. Renseignez :
   - **Location** : une URL uniquement destinée à l'affichage et aux liens, par exemple l'URL de votre console AWS.
   - **Instance Label** : un libellé qui distingue cette connexion des autres, par exemple `Production AWS account`.
   - **Access Key ID** : l'identifiant de clé, qui ressemble à `AKIAIOSFODNN7EXAMPLE`.
   - **Secret Access Key** : la partie secrète.
4. Enregistrez.

DefectDojo vérifie immédiatement l'identifiant auprès d'AWS, de sorte qu'une clé incorrecte ou supprimée est signalée ici plutôt qu'au premier déclenchement d'une alerte. Cette vérification confirme uniquement que l'identifiant est valide ; le fait qu'il puisse publier sur un topic donné est vérifié au moment où vous définissez la destination.

**Il n'y a pas de région à saisir.** La région fait partie de l'ARN du topic, si bien qu'une seule connexion peut publier vers des topics dans plusieurs régions, et il n'y a pas de second paramètre qui pourrait entrer en contradiction avec l'ARN.

### 3. Trouver l'ARN du topic

Une destination SNS utilise l'ARN du topic.

1. Dans la console SNS, ouvrez le topic.
2. Copiez l'**ARN** en haut de la page. Il ressemble à `arn:aws:sns:us-east-1:123456789012:security-alerts`.

Contrairement à une URL de workflow Teams, un ARN n'est pas un secret : il désigne un topic, et y publier nécessite l'identifiant présent sur la connexion. C'est pourquoi une seule connexion SNS peut servir plusieurs topics.

Les topics FIFO (un ARN se terminant par `.fifo`) ne sont pas pris en charge. Ils nécessitent un groupe de messages et un ID de déduplication, des règles d'ordonnancement qu'une alerte n'a rien pour fournir. Utilisez un topic standard.

## Envoyer un message de test

Partout où une destination de messagerie est configurée, **Send test message** délivre un court message par exactement le même chemin qu'utilise une véritable alerte, et indique ce que le fournisseur a répondu.

Utilisez-le pour vérifier ce qu'il est facile de mal configurer : pour Slack, que l'ID de canal est correct et que le bot peut y publier ; pour Teams, que l'URL du workflow fonctionne toujours ; pour l'e-mail, que l'adresse est joignable ; pour SNS, que la clé peut publier sur ce topic. La réponse du fournisseur lui-même est transmise telle quelle, de sorte qu'une invitation Slack manquante se traduit par un message vous invitant à inviter le bot plutôt que par un échec générique.

Un test réussi débloque également une connexion qui a été désactivée automatiquement (voir [Quand une connexion cesse de fonctionner](#when-a-connection-stops-working)).

## Créer une alerte

Il existe deux façons d'y arriver. Toutes deux produisent la même chose : une règle Rules Engine 2.0.

### La page des alertes

Le chemin court, pour le cas courant consistant à annoncer de nouvelles constatations issues d'un import.

1. Allez dans **Connect > Downstream** et sélectionnez **Create Alert** sur une connexion de messagerie, ou ouvrez directement **Messaging Alerts**.
2. Sélectionnez **New Alert** et renseignez :
   - **Name** : à quoi sert cette alerte, par exemple `New highs to the security channel`.
   - **Alert** : de quoi il s'agit. **New findings from an import** est actuellement la seule option.
   - **Send over** : la connexion de messagerie.
   - **Where it delivers** : le champ de destination propre au fournisseur, donc un ID de canal Slack, un libellé de canal Teams optionnel, une liste d'adresses e-mail, ou un ARN de topic SNS.
   - **Severity** : le plancher, de **Critical only** à **Every severity**.
   - **Mode** : **Simulate** enregistre ce qui aurait été envoyé sans l'envoyer, **Live** envoie réellement.
3. Sélectionnez **Create Alert**.

La page liste les alertes qu'elle a créées, avec le déclencheur, le plancher de sévérité, et un interrupteur pour activer ou désactiver chacune d'elles.

Commencez en mode **Simulate** si vous voulez voir ce qu'une alerte aurait capté avant que quiconque n'en entende parler sur son canal. La règle s'exécute, les livraisons sont enregistrées, et rien n'est envoyé.

Les alertes sont des règles, elles peuvent donc aussi être ouvertes dans l'éditeur de règles depuis la même liste. Une fois qu'une règle a été modifiée en quelque chose que le formulaire ne peut plus exprimer, comme une seconde branche ou un second message, la liste propose l'éditeur de règles à la place du formulaire, plutôt qu'un formulaire qui aplatirait discrètement le travail supplémentaire.

### L'éditeur de règles

Le chemin complet, pour tout ce que le formulaire ne couvre pas.

1. Allez dans **Automation > Rules Engine 2.0** et créez une règle.
2. Ajoutez un déclencheur. Pour des alertes portant sur des Constatations nouvellement importées, utilisez le déclencheur d'événement Finding sur **created**. Les imports sont regroupés par lots, si bien qu'un import produit une seule alerte plutôt qu'une par Constatation.
3. Ajoutez des conditions déterminant l'éligibilité, par exemple une sévérité minimale de Élevée.
4. Ajoutez un nœud de message pour le fournisseur souhaité (**Send a Slack Message**, **Send a Microsoft Teams Message**, **Send an Email**, ou **Publish to an SNS Topic**) et définissez :
   - **Connection** : la connexion de messagerie que vous avez créée.
   - **Destination** : la destination propre au fournisseur, donc un ID de canal pour Slack, un libellé de canal optionnel pour Teams, des destinataires pour l'e-mail, ou un ARN de topic pour SNS.
5. Enregistrez la règle et activez-la.

Rien n'est envoyé si aucune Constatation ne correspond aux conditions, si bien qu'une règle filtrée sur Élevée et au-dessus reste silencieuse sur un import n'ayant apporté que des Constatations de sévérité Faible.

### Règles écrites avant les connecteurs de messagerie

Un nœud de message envoie via une connexion, et seulement via une connexion. Les nœuds Slack, Teams et e-mail se rabattaient auparavant sur les paramètres globaux de l'instance sous **Settings > Notifications** lorsqu'aucune connexion n'était choisie. Ce n'est plus le cas.

Une règle écrite de cette façon continue de s'exécuter, et son nœud de message enregistre une livraison ignorée indiquant qu'il ne nomme aucune connexion. Pour la corriger, ouvrez la règle, choisissez une connexion et une destination sur le nœud, puis enregistrez. Une livraison déjà enregistrée peut être rejouée depuis la liste des livraisons une fois que le nœud nomme une connexion.

La connexion est un champ obligatoire sur chaque nœud de message, l'éditeur de règles en demande donc une avant que la règle puisse être enregistrée.

## Quand une connexion cesse de fonctionner

Un jeton de bot révoqué, un workflow supprimé, ou une clé d'accès AWS supprimée fait échouer toutes les alertes qu'elle sert. Plutôt que d'enregistrer le même échec pour chaque événement, DefectDojo compte les échecs d'identifiants consécutifs par destination et arrête l'envoi après quelques-uns. La connexion indique quelle destination a été désactivée et pourquoi.

Pour récupérer : corrigez l'identifiant (réinstallez l'application Slack et collez le nouveau jeton, recréez le workflow Teams et collez la nouvelle URL, ou créez une nouvelle clé d'accès AWS), puis envoyez un message de test à cette destination, ce qui la réactive en cas de succès, ou utilisez directement l'action de réactivation.

Seuls les échecs d'identifiants provoquent cela. Un message rejeté parce qu'un ID de canal Slack est incorrect, que le bot n'est pas invité, qu'une adresse e-mail n'existe pas, ou qu'une politique IAM n'autorise pas la publication sur un topic donné, ne désactive rien, car l'identifiant est valide et corriger la destination ou la politique devrait fonctionner immédiatement.

## Alertes et notifications ensemble

Les connecteurs de messagerie ne remplacent pas les notifications. Les paramètres globaux de l'instance pour Slack, Teams et e-mail sous **Settings > Notifications**, les notifications personnelles, et la matrice de notification continuent tous de fonctionner exactement comme configurés. Ce sont eux qui annoncent les propres événements de DefectDojo ; un connecteur de messagerie, lui, envoie ce qu'une règle que vous avez écrite lui confie.

Un point à surveiller : si une alerte publie sur le même canal ou la même adresse que le paramètre global de l'instance annonce déjà, cette destination reçoit les deux messages. Configurez l'un ou l'autre pour une destination donnée.

## Limites

- Le libellé des messages n'est pas encore personnalisable. Les alertes utilisent le texte intégré de DefectDojo.
- Les messages sont à sens unique. DefectDojo ne lit pas les réponses, et il n'y a ni boutons ni éléments interactifs dans le message.
- Les fils de discussion, la modification de message, et les messages directs à des utilisateurs individuels ne sont pas pris en charge. Les notifications personnelles continuent d'utiliser le système de notification existant.
- Une connexion Teams n'atteint qu'un seul canal, car c'est l'URL du workflow qui adresse le canal.
- Les messages SNS sont en texte brut. Un topic peut diffuser à la fois vers des abonnés e-mail, SMS, Lambda et HTTPS, il n'existe donc pas de format unique adapté à tous, et aucune variante par protocole n'est publiée.
- Les topics SNS FIFO ne sont pas pris en charge.
- Les rapports et autres pièces jointes ne peuvent pas encore être envoyés. Les alertes sont des messages avec des liens de retour vers DefectDojo.
- La page des alertes couvre les nouvelles constatations issues d'un import. Tout le reste se construit dans l'éditeur de règles.
