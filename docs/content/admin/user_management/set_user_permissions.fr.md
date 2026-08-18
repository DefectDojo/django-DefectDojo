---
title: Définir les autorisations d'un utilisateur
description: Comment attribuer des rôles et des autorisations à un utilisateur, ainsi
  que le statut de superutilisateur
weight: 2
audience: pro
aliases:
- /fr/en/customize_dojo/user_management/set_user_permissions
---

> **Fonctionnalité DefectDojo Pro.** Le système RBAC Membres / Groupes / Rôles globaux décrit sur cette page fait partie de DefectDojo Pro. La version open source de DefectDojo utilise le modèle [Utilisateurs autorisés](../os__authorized_users/) — consultez cette page pour le contrôle d'accès en version open source, ainsi que les [notes de mise à niveau 3.0](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization) si vous passez d'une édition à l'autre.

## Introduction aux types d'autorisations

Chaque utilisateur peut se voir attribuer quatre types d'autorisations différents :

* Les utilisateurs peuvent être ajoutés en tant que **Membres de Produits ou de Types de produit**. Cela leur permet de consulter et d'interagir avec les types de données (Types de produit, Produits, Engagements, Tests et Constatations) dans DefectDojo, selon le rôle qui leur est attribué sur le Produit concerné. Un utilisateur peut avoir plusieurs adhésions à des Produits ou Types de produit, avec des niveaux d'accès différents.
​
* Les utilisateurs peuvent également se voir attribuer des **Autorisations de configuration**, qui leur permettent d'accéder aux pages de configuration de DefectDojo. Les Autorisations de configuration ne sont pas liées aux Produits ou aux Types de produit.
​
* Les utilisateurs peuvent se voir attribuer des **Rôles globaux**, qui leur donnent un niveau d'accès standardisé à tous les Produits et Types de produit.
​
* Les utilisateurs peuvent être configurés en tant que **Superutilisateurs** : des rôles de niveau administrateur qui leur donnent le contrôle et l'accès à toutes les données et à la configuration de DefectDojo.

Vous pouvez également créer des Groupes si vous souhaitez attribuer une adhésion à un Produit, des Autorisations de configuration ou des Rôles globaux à un groupe d'utilisateurs en même temps. Si vous avez un grand nombre d'utilisateurs dans DefectDojo, comme une équipe de test dédiée à un Produit particulier, les Groupes peuvent être une fonctionnalité plus utile.

## Superutilisateurs \& Rôles globaux

Une partie de votre configuration de Contrôle d'accès basé sur les rôles (RBAC) peut nécessiter la création de Superutilisateurs supplémentaires, ou d'utilisateurs disposant de Rôles globaux.

* Les Superutilisateurs (Admins) n'ont aucune limitation dans le système. Ils peuvent modifier tous les paramètres, gérer les utilisateurs et disposent d'un accès en lecture / écriture à toutes les données. Ils peuvent également modifier les règles d'accès de tous les utilisateurs de DefectDojo. Les Superutilisateurs reçoivent également les notifications pour tous les problèmes système et alertes.
* Les utilisateurs disposant de Rôles globaux peuvent consulter et interagir avec tout type de données (Types de produit, Produits, Engagements, Tests et Constatations) dans DefectDojo, selon le Rôle qui leur est attribué. Pour en savoir plus sur chaque Rôle et les privilèges associés, veuillez consulter notre article Introduction aux rôles.
* Les utilisateurs peuvent également se voir attribuer des Autorisations de configuration spécifiques, leur permettant d'accéder à certaines pages de configuration de DefectDojo. Par défaut, les utilisateurs ne disposent d'aucune Autorisation de configuration.

Par défaut, le premier compte créé sur une nouvelle instance DefectDojo dispose des autorisations de Superutilisateur. Cet utilisateur pourra modifier les autorisations de tous les utilisateurs DefectDojo créés par la suite. Seul un Superutilisateur existant peut ajouter un autre superutilisateur, ou attribuer un Rôle global à un utilisateur.

### Attribuer le statut de Superutilisateur ou un Rôle global à un utilisateur existant

1. Accédez à la page 👤 Utilisateurs \> Utilisateurs dans la barre latérale. Vous verrez une liste de tous les comptes enregistrés dans DefectDojo, ainsi que le statut Actif, les Rôles globaux et les autres données pertinentes de chaque compte.
​
![image](images/Set_a_User's_Permissions.png)
​
2. Cliquez sur le nom du compte auquel vous souhaitez accorder les privilèges de Superutilisateur. Vous accéderez ainsi à sa Page utilisateur.
​
3. Dans la section Informations par défaut de sa Page utilisateur, ouvrez le menu ☰ et sélectionnez Modifier.
​
![image](images/Set_a_User's_Permissions_2.png)

4. Depuis la page Modifier l'utilisateur :
​
Pour le Statut de superutilisateur, cochez la case ☑️ Statut de superutilisateur, située dans les Informations par défaut de l'utilisateur.
​
Pour attribuer un Rôle global, sélectionnez-en un dans le menu déroulant Rôle global en bas de la page.
​
![image](images/Set_a_User's_Permissions_3.png)
​
5. Cliquez sur Envoyer pour valider ces modifications.

## Adhésion à un Produit et à un Type de produit

Par défaut, tout nouveau compte créé dans DefectDojo n'a pas l'autorisation de consulter les données au niveau des Produits. Il devra se voir attribuer une adhésion à chaque Produit qu'il souhaite consulter et avec lequel il souhaite interagir.

* L'adhésion à un Produit et à un Type de produit ne peut être configurée que par des **Superutilisateurs, Mainteneurs ou Propriétaires**.
* Les **Mainteneurs et Propriétaires** ne peuvent configurer l'adhésion que sur les Produits / Types de produit auxquels ils sont déjà affectés.
* Les **Mainteneurs et Propriétaires globaux** peuvent configurer l'adhésion sur n'importe quel Produit ou Type de produit, tout comme les **Superutilisateurs**.

Les utilisateurs peuvent avoir deux types d'adhésion simultanément au niveau du **Produit** :

* Le Rôle conféré par leur adhésion au Type de produit sous-jacent, le cas échéant
* Leur Rôle spécifique au Produit, s'il en existe un.

Si un utilisateur a déjà été ajouté en tant que membre d'un Type de produit et n'a pas besoin d'un niveau d'autorisation supplémentaire sur un Produit spécifique, il n'est pas nécessaire de l'ajouter en tant que Membre du Produit.

### Ajouter un nouveau Membre

1. Accédez au Produit ou au Type de produit auquel vous souhaitez affecter un utilisateur. Vous pouvez sélectionner le Produit dans la liste sous **Produits \> Tous les produits**.

![image](images/Set_a_User's_Permissions_4.png)

2. Repérez le titre **Membres**, cliquez sur le menu **☰**, puis sélectionnez **\+ Ajouter des utilisateurs**.
3. Vous accéderez ainsi à une page où vous pouvez **Enregistrer de nouveaux Membres**. Sélectionnez un Utilisateur dans le menu déroulant Utilisateurs.
4. Sélectionnez le Rôle que vous souhaitez attribuer à cet Utilisateur sur ce Produit ou ce Type de produit : **Importateur API, Lecteur, Rédacteur, Mainteneur** ou **Propriétaire.**
​
![image](images/Set_a_User's_Permissions_5.png)

Un utilisateur ne peut pas être ajouté en tant que Membre d'un Produit ou d'un Type de produit sans se voir également attribuer un Rôle. Si vous ne savez pas quel Rôle attribuer à un nouvel utilisateur, **Lecteur** est une bonne option « par défaut ». Cela permettra de garder l'état de votre Produit sécurisé jusqu'à ce que vous ayez pris votre décision finale concernant son Rôle.

### Modifier ou Supprimer un Membre

Le Rôle des Membres peut être modifié au sein d'un Produit ou d'un Type de produit.

Sur la page **Produit** ou **Type de produit**, accédez au titre **Membres** et cliquez sur le bouton **⋮** à côté de l'Utilisateur que vous souhaitez Modifier ou Supprimer.

![image](images/Set_a_User's_Permissions_6.png)

📝 **Modifier** vous amène à l'écran **Modifier le membre**, où vous pouvez changer le **Rôle** de cet utilisateur (parmi **Importateur API, Lecteur, Rédacteur, Mainteneur** ou **Propriétaire**, vers un autre choix).

🗑️ **Supprimer** retire entièrement l'adhésion d'un Utilisateur. Cela ne supprime pas les contributions ni les modifications que l'Utilisateur a apportées au Produit ou au Type de produit.

* Si vous ne pouvez pas Modifier ou Supprimer l'adhésion d'un utilisateur (le **⋮** n'est pas visible), c'est parce que cette adhésion lui est conférée au niveau du **Type de produit**.
* Un utilisateur peut avoir deux niveaux d'adhésion au sein d'un Produit \- l'un attribué au niveau du **Type de produit** et l'autre au niveau du **Produit**.

#### Attribuer un rôle Produit supplémentaire à un utilisateur ayant un rôle Type de produit associé

Si un Utilisateur dispose d'un Rôle au niveau du Type de produit, il se verra également attribuer une adhésion avec ce Rôle sur chaque Produit sous-jacent de la catégorie. Cependant, si vous souhaitez que cet Utilisateur dispose d'un Rôle spécial sur un Produit particulier au sein de ce Type de produit, vous pouvez lui attribuer un Rôle supplémentaire au niveau du Produit.

1. Depuis la page du Produit, accédez au titre **Membres**, cliquez sur le menu **☰**, puis sélectionnez **\+ Ajouter des utilisateurs** (comme si vous ajoutiez un nouvel Utilisateur au Produit).
2. Sélectionnez le nom de l'Utilisateur dans le menu déroulant, puis sélectionnez le Rôle Produit que vous souhaitez lui attribuer.

Un Rôle Produit prévaut sur le Rôle Type de produit ou le Rôle global standard d'un utilisateur. Par exemple, si un Utilisateur a un Rôle Type de produit de **Lecteur**, mais est également désigné comme **Propriétaire** sur un Produit imbriqué dans ce Type de produit, il disposera d'autorisations **Propriétaire** supplémentaires pour ce Produit uniquement.

Cependant, cela ne fonctionne pas dans l'autre sens. Si un Utilisateur a un Rôle Type de produit ou un Rôle global de **Propriétaire**, lui attribuer un rôle **Lecteur** sur un Produit particulier ne lui retirera pas ses autorisations de **Propriétaire**. **Les Rôles ne peuvent pas retirer les autorisations accordées à un Utilisateur par d'autres Rôles, ils ne peuvent qu'ajouter des autorisations supplémentaires.**

## Autorisations de configuration

De nombreuses boîtes de dialogue de configuration et points de terminaison API peuvent être activés pour des utilisateurs ou des groupes d'utilisateurs, indépendamment de leur statut de superutilisateur. Ces Autorisations de configuration permettent aux utilisateurs standard d'accéder à certaines parties de DefectDojo et d'y contribuer, en dehors de leur affectation habituelle à un Produit ou un Rôle Produit.

Les Autorisations de configuration ne sont pas liées à un Produit ou à un Type de produit spécifique \- les utilisateurs peuvent se voir attribuer des autorisations de configuration sans avoir besoin d'autres statuts ou d'une adhésion à un Produit / Type de produit.
​
### Liste des Autorisations de configuration

* **Gestionnaire d'identifiants :** Accès à la page ⚙️Configuration \> Gestionnaire d'identifiants
* **Environnements de développement :** Gérer la liste Engagements \> Environnements
* **Modèles de constatation :** Accès à la page Constatations \> Modèles de constatation
* **Groupes** : Accéder à la page 👤Utilisateurs \> Groupes
* **Instances Jira :** Accéder à la page ⚙️Configuration \> JIRA
* **Types de langage** : Accéder au point de terminaison API [Types de langage](/automation/api/languages/)
* **Bannière de connexion** : Modifier la page ⚙️Configuration \> Bannière de connexion
* **Annonces** : Accéder à ⚙️Configuration \> Annonces
* **Types de note :** Accéder à la page ⚙️Configuration \> Types de note
* **Types de produit :** n/a
* **Questionnaires** : Accéder à la page Questionnaires \> Tous les questionnaires
* **Questions** : Accéder à la page Questionnaires \> Questions
* **Réglementations** : Accéder à la page ⚙️Configuration \> Réglementations
* **Configuration SLA :** Accéder à la page ⚙️Configuration \> Configuration SLA
* **Types de test :** Ajouter ou modifier un Type de test (sous Engagements \> Types de test)
* **Configuration des outils :** Accéder à la page **⚙️Configuration \> Types d'outils**
* **Types d'outils :** Accéder à la page ⚙️Configuration \> Types d'outils
* **Utilisateurs :** Accéder à la page 👤Utilisateurs \> Utilisateurs

### Attribuer des Autorisations de configuration à un Utilisateur

**Seuls les Superutilisateurs peuvent attribuer des Autorisations de configuration à un Utilisateur**.

1. Accédez à la page 👤 Utilisateurs \> Utilisateurs dans la barre latérale. Vous verrez une liste de tous les comptes enregistrés dans DefectDojo, ainsi que le statut Actif, les Rôles globaux et les autres données pertinentes de chaque compte.
​
![image](images/Set_a_User's_Permissions_7.png)

2. Cliquez sur le nom du compte que vous souhaitez modifier.
​
3. Accédez à la Liste des Autorisations de configuration. Elle se trouve sur le côté droit de la Page utilisateur.
​
4. Sélectionnez les Autorisations de configuration utilisateur que vous souhaitez ajouter.
​
Pour une répartition détaillée des Autorisations de configuration utilisateur, veuillez consulter notre [Tableau des autorisations](../user_permission_chart/).
