---
title: Configurer les notifications à l'échelle du système
description: Comment configurer les notifications personnelles et système
aliases:
- /fr/en/customize_dojo/notifications/configure_system_notifs
---

DefectDojo dispose de deux types de notifications différents : **Personnelles** (envoyées à un seul compte) et **Système** (envoyées à tous les utilisateurs).

Les Notifications personnelles d'un compte et les Notifications système globales peuvent être configurées depuis la même page : **⚙️Configuration \> Notifications** dans la barre latérale.

![image](images/Configure_System_&_Personal_Notifications.png)

## Configurer les notifications système (interface classique)

**Vous devez disposer d'un accès Superutilisateur pour modifier les notifications à l'échelle du système.**

1. Commencez par la page Notifications (⚙️ **Configuration \> Notifications** dans la barre latérale).
2. Dans le menu déroulant Portée, vous pouvez sélectionner l'ensemble de notifications que vous souhaitez modifier.
3. Sélectionnez Notifications système.
4. Cochez la méthode d'envoi de notification que vous souhaitez utiliser pour chaque type de notification. Vous pouvez en sélectionner plusieurs.

![image](images/Configure_System_&_Personal_Notifications_2.png)

Pour définir les destinations des notifications par e-mail à l'échelle du système (E-mail, Slack ou MS Teams), consultez notre [Guide](../email_slack_teams).

## Notifications modèles

Les Superutilisateurs ont également accès à un formulaire « Modèle ».  Le formulaire Modèle vous permet de définir les Notifications personnelles activées par défaut pour tout nouvel utilisateur.

## Où sont envoyées les notifications système

Les notifications système sont envoyées à :
- l'adresse e-mail unique spécifiée dans les Paramètres système (si activé)
- tous les utilisateurs DefectDojo disposant d'un compte et des autorisations RBAC appropriées
- le compte Slack ou Teams à l'échelle du système.

Comme pour toute notification dans DefectDojo, les Notifications système ne seront envoyées qu'aux utilisateurs ayant accès aux données concernées.  Ainsi, même si des Notifications de produit sont configurées à l'échelle du système, les utilisateurs ne recevront des notifications que pour les Produits qu'ils sont autorisés à consulter.

Cette restriction ne s'applique pas aux Notifications système envoyées à une adresse e-mail ou un canal Slack spécifique.

Consultez notre guide sur le [Contrôle d'accès basé sur les rôles](../../user_management/about_perms_and_roles/) pour plus d'informations sur le RBAC et la définition des autorisations.

Cependant, les comptes E-mail, Slack et Teams système connectés ne peuvent pas appliquer le RBAC, car ils ne sont associés à aucun utilisateur DefectDojo spécifique.  **Toutes les notifications à l'échelle du système sélectionnées seront envoyées à ces emplacements, vous devez donc vous assurer que ces canaux ne sont accessibles qu'à des personnes spécifiques de votre organisation.**
