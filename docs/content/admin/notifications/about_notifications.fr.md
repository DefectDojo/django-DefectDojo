---
title: À propos des notifications et des 🔔 alertes
description: Découvrez les notifications et les alertes intégrées à l'application
aliases:
- /fr/en/customize_dojo/notifications/about_notifications
---

DefectDojo vous tient informé de diverses manières. Des notifications peuvent être envoyées pour les Engagements à venir, les [mentions d'utilisateur](/triage_findings/findings_workflows/intro_to_findings/#notes-and-mentions), l'expiration des SLA, et d'autres événements du logiciel.

Cet article présente un aperçu des notifications aux niveaux Système et Personnel.

## Types de notification

DefectDojo gère les notifications de deux manières différentes :

* Les **Notifications à l'échelle du système** sont envoyées à tous les utilisateurs.
* **Les Notifications personnelles sont définies par chaque utilisateur individuellement, et sont reçues en plus des Notifications à l'échelle du système.**

Dans les deux cas, les règles de [Contrôle d'accès basé sur les rôles](../../user_management/about_perms_and_roles/) s'appliquent, de sorte que les utilisateurs ne recevront pas de notifications d'activité pour les Produits ou Types de produit (ou leurs objets associés) auxquels ils n'ont pas accès.

## Méthodes d'envoi des notifications

Il existe quatre méthodes d'envoi pour les notifications DefectDojo :

* DefectDojo peut partager des **🔔 Alertes,** stockées sous forme de liste dans l'interface DefectDojo
* DefectDojo peut envoyer des notifications à une adresse **E-mail**
* DefectDojo peut envoyer des notifications à **Slack,** dans un canal partagé ou individuel
* DefectDojo peut également envoyer des notifications à **Microsoft Teams** dans un canal partagé

Les notifications peuvent être envoyées vers plusieurs destinations simultanément.

Pour recevoir des notifications Slack et Teams, vous devez disposer d'une intégration fonctionnelle. Pour plus d'informations sur la configuration de cette intégration, consultez notre [Guide](../email_slack_teams).

## Alertes intégrées à l'application

Le système d'Alertes de DefectDojo vous tient informé de toute l'activité des Produits ou du système.

### La Liste des alertes

La Liste des alertes est toujours visible dans le coin supérieur droit de DefectDojo, et contient une liste compacte des notifications. Cliquer sur chaque Alerte vous amène directement à la page correspondante dans DefectDojo.

Vous pouvez ouvrir votre Liste des alertes en cliquant sur l'**icône 🔔▼** dans le coin supérieur droit :

![image](images/About_In-App_Alerts.png)

Pour voir toutes vos notifications, avec des détails supplémentaires, vous pouvez cliquer sur le bouton **Voir toutes les alertes \>**, qui ouvrira la **Page des alertes**.

Vous pouvez également **Effacer toutes les alertes \>** depuis la Liste des alertes.

### La Page des alertes

La Page des alertes stocke toutes vos Alertes dans DefectDojo avec des détails supplémentaires. Sur cette page, vous pouvez lire la description de chaque Alerte dans DefectDojo, et les retirer de la file d'attente des alertes une fois que vous n'en avez plus besoin.

![image](images/About_In-App_Alerts_2.png)

Pour retirer une ou plusieurs Alertes de la Page des alertes, cochez la case vide à côté de celles-ci, puis cliquez sur le bouton **Supprimer la sélection** dans le coin inférieur droit de la Page.

### Remarques sur les alertes

* Lire une Alerte, ou ouvrir la Page des alertes, ne retire aucune Alerte du compteur situé à côté de l'icône de cloche. Cela vous permet d'accéder facilement aux alertes passées pour les utiliser comme rappels ou comme journal d'activité personnel.
* L'utilisation de la fonction **Effacer toutes les alertes \>** dans le Menu des alertes efface également entièrement la **Page des alertes**, utilisez donc cette fonctionnalité avec prudence.
* Retirer une Alerte n'affecte que votre propre Liste des alertes \- cela n'affecte pas les Alertes des autres utilisateurs.
* Retirer une Alerte ne supprime aucun historique d'importation ni journal d'activité de DefectDojo.

## Restreindre les notifications de demande de révision (Pro)

Si une révision est demandée à tous les réviseurs éligibles, chaque personne éligible sur cet actif est notifiée. Cela représente beaucoup de courrier pour un réviseur qui ne s'occupe que d'une partie de votre parc.

Dans l'interface DefectDojo Pro, vous pouvez restreindre vos propres notifications de demande de révision. Sur votre page de paramètres de notification, sous **Demandes de révision** :

* **Portée des demandes de révision** — *Tout* (valeur par défaut) vous notifie de tout ce que vous pouvez voir. *Sélectionné* vous restreint aux actifs et types d'actifs que vous choisissez.
* **Actifs des demandes de révision** / **Types d'actifs des demandes de révision** — la portion du parc dont vous souhaitez être informé. Une demande correspond si elle concerne l'un de vos actifs sélectionnés *ou* l'un de vos types d'actifs sélectionnés.

Deux points à clarifier :

* Choisir *Sélectionné* et ne rien sélectionner signifie **aucun**, et non pas tous.
* La restriction supprime la notification, **pas la demande**. Vous restez un réviseur sollicité et la demande continue d'apparaître dans votre file d'attente [Mon travail](/metrics_reports/dashboards/pro__my_work/) sous **En attente de ma révision** — vous n'êtes simplement pas notifié à ce sujet. Ceci est intentionnel : la file d'attente constitue l'enregistrement durable, les notifications ne sont qu'un rappel.

Cette restriction prévaut également sur la surcharge au niveau système décrite ci-dessous, de sorte qu'un réviseur qui s'est exclu du périmètre n'est pas notifié même lorsque `review_requested` est configuré pour prévaloir sur les préférences personnelles.

La restriction peut également être configurée via l'API sur le point de terminaison des notifications, ce qui constitue la solution pratique si vous configurez de nombreux réviseurs à la fois.

## Notifications d'attribution de travail (Pro)

Lorsque des Constatations vous sont attribuées, la notification **Travail attribué** vous indique leur nombre et renvoie vers votre file d'attente Mon travail.

Elle est agrégée par personne plutôt que par Constatation : attribuer une centaine de Constatations envoie un seul message, pas cent. Comme pour les demandes de révision, l'attribution est visible dans votre file d'attente, que la notification vous parvienne ou non.

## Considérations pour la version open source

### Surcharges spécifiques

Les paramètres de notification système (portée : system) décrivent l'envoi de notifications aux super-administrateurs. Les paramètres de notification utilisateur (portée : personal) décrivent l'envoi de notifications à un utilisateur spécifique.

Cependant, il existe un cas d'usage spécifique où l'utilisateur décide de désactiver les notifications (pour réduire le bruit), mais le paramètre système est utilisé pour outrepasser ce comportement. Ces surcharges s'appliquent par défaut uniquement à `user_mentioned` et `review_requested`.

La portée de ce paramètre est personnalisable (voir la variable d'environnement `DD_NOTIFICATIONS_SYSTEM_LEVEL_TRUMP`).

Pour plus d'informations sur ce comportement, consultez la [pull request associée #9699](https://github.com/DefectDojo/django-DefectDojo/pull/9699/)

### Webhooks (expérimental)

DefectDojo prend également en charge les webhooks, qui suivent les mêmes événements que les autres notifications (vous pouvez être notifié dans les mêmes situations). Les détails de configuration sont décrits sur [la page correspondante](/automation/api/notification_webhooks/).
