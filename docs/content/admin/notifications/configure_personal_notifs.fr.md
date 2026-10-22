---
title: Configurer les notifications personnelles
description: Configurer les notifications pour un compte personnel
aliases:
- /fr/en/customize_dojo/notifications/configure_personal_notifs
---

## Configurer les notifications personnelles

Les Notifications personnelles sont envoyées en plus des Notifications à l'échelle du système, et s'appliquent à tout Produit, Type de produit ou autre type de données auquel vous avez accès. Les préférences de Notifications personnelles ne s'appliquent qu'à un seul utilisateur, et ne peuvent être définies que sur le compte qui les configure.

![image](images/Configure_System_&_Personal_Notifications.png)

Les notifications système sont définies par un Superutilisateur DefectDojo et ne peuvent pas être désactivées par un utilisateur individuel.

1. Commencez par la page Notifications (⚙️**Configuration \> Notifications** dans la barre latérale).
2. Dans le menu déroulant **Portée**, vous pouvez sélectionner l'ensemble de notifications que vous souhaitez modifier.
3. Sélectionnez Notifications personnelles.
4. Cochez la méthode de notification que vous souhaitez utiliser pour chaque type de notification. Vous pouvez en sélectionner plusieurs.

Les Notifications personnelles ne peuvent pas être envoyées via Microsoft Teams, car Teams ne permet de publier que des notifications globales dans un canal unique.

### Recevoir des notifications personnelles pour un Produit spécifique

En plus des notifications personnelles standard, les Utilisateurs DefectDojo peuvent également recevoir des notifications pour l'activité d'un Produit spécifique. Cela est utile lorsqu'un utilisateur doit surveiller certains Produits de plus près.

![image](images/Configure_System_&_Personal_Notifications_3.png)

Cette configuration peut être modifiée depuis la section **Notifications** sur la page **Produit** : par exemple `your-instance.defectdojo.com/product/{id}`.

À partir de là, vous pouvez définir si vous souhaitez recevoir des notifications **🔔 Alerte**, **E-mail** ou **Slack** pour les actions effectuées sur ce Produit en particulier. Ces notifications s'ajoutent à toute notification à l'échelle du système que vous recevez déjà.

Microsoft Teams ne peut envoyer aucun type de notification personnelle, les notifications Teams ne peuvent donc pas être choisies depuis ce menu.

Les notifications personnelles par e-mail seront toujours envoyées à l'adresse e-mail associée à votre identifiant DefectDojo. Pour configurer un compte Slack personnel afin de recevoir des notifications, consultez notre [Guide](../email_slack_teams/#send-personal-notifications-to-slack).
