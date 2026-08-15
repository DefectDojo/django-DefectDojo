---
title: Définir les autorisations dans Pro
description: Refonte, fonctionnalité Pro
weight: 3
audience: pro
aliases:
- /fr/en/customize_dojo/user_management/pro_permissions_overhaul
---

## Introduction aux types d'autorisations

Chaque utilisateur peut se voir attribuer quatre types d'autorisations différents :

* Les utilisateurs peuvent être affectés comme **Members à des Produits ou des Types de produit**. Cela leur permet de consulter et d'interagir avec les types de données (Types de produit, Produits, Engagements, Tests et Constatations) dans DefectDojo, selon le rôle qui leur est attribué sur le Produit spécifique. Les utilisateurs peuvent avoir plusieurs memberships sur des Produits ou des Types de produit, avec différents niveaux d'accès.  
​
* Les utilisateurs peuvent également se voir attribuer des **Configuration Permissions**, qui leur permettent d'accéder aux pages de configuration de DefectDojo. Les Configuration Permissions ne sont pas liées aux Produits ou aux Types de produit.  
​
* Les utilisateurs peuvent se voir attribuer des **Global Roles**, qui leur donnent un niveau d'accès standardisé à tous les Produits et Types de produit.  
​
* Les utilisateurs peuvent être configurés comme **Superusers** : des rôles de niveau administrateur qui leur donnent le contrôle et l'accès à toutes les données et à la configuration de DefectDojo.

Vous pouvez également créer des Groups si vous souhaitez attribuer un Product Membership, des Configuration Permissions ou des Global Roles à un groupe d'utilisateurs en même temps. Si vous avez un grand nombre d'utilisateurs dans DefectDojo, comme une équipe de test dédiée à un Produit particulier, les Groups peuvent être une fonctionnalité plus pratique. 

## Superusers et Global Roles

Une partie de votre configuration de contrôle d'accès basé sur les rôles (RBAC) peut nécessiter la création de Superusers supplémentaires, ou d'utilisateurs disposant de Global Roles.

* Les Superusers (Admins) n'ont aucune limitation dans le système. Ils peuvent modifier tous les paramètres, gérer les utilisateurs et disposent d'un accès en lecture/écriture à toutes les données. Ils peuvent également modifier les règles d'accès de tous les utilisateurs de DefectDojo. Les Superusers reçoivent également les notifications pour tous les problèmes et alertes système.
* Les utilisateurs disposant de Global Roles peuvent consulter et interagir avec tout type de données (Types de produit, Produits, Engagements, Tests et Constatations) dans DefectDojo, selon le Role qui leur est attribué. Pour plus d'informations sur chaque Role et les privilèges associés, veuillez consulter notre article Introduction aux rôles.
* Les utilisateurs peuvent également se voir attribuer des Configuration Permissions spécifiques, leur permettant d'accéder à certaines pages de configuration de DefectDojo. Les utilisateurs ne disposent d'aucune Configuration Permission par défaut.

Par défaut, le premier compte créé sur une nouvelle instance DefectDojo dispose des autorisations Superuser. Cet utilisateur pourra modifier les autorisations de tous les utilisateurs DefectDojo créés par la suite. Seul un Superuser existant peut ajouter un autre superuser, ou attribuer un Global Role à un utilisateur.

Les autorisations dans <span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> ont été simplifiées, afin de faciliter l'attribution de l'accès aux objets.  Cette fonctionnalité est accessible via l'[interface Pro](/get_started/about/ui_pro_vs_os/).

### Ouvrir la fenêtre des autorisations 

![image](images/pro_permissions.png)

Lorsque vous consultez un Type de produit ou un Produit, vous pouvez ouvrir la fenêtre des autorisations pour définir rapidement les autorisations. Ce menu se trouve dans un tableau en cliquant sur les points horizontaux **"⋮"**. Si vous consultez une page individuelle **Produit** ou **Type de produit**, ce menu se trouve sous l'icône d'engrenage bleue ‘⚙️’.

## Définir les autorisations depuis la fenêtre des autorisations

![image](images/pro_permissions_2.png)

1. En haut de cette fenêtre, vous pouvez choisir de gérer les autorisations pour un utilisateur individuel ou pour un [groupe d'utilisateurs](../create_user_group).
2. Ici, vous pouvez sélectionner un utilisateur ou un groupe à ajouter au Produit, et sélectionner le [Role](../about_perms_and_roles) que vous souhaitez attribuer à cet utilisateur.
3. Dans le tableau du bas, vous pouvez voir la liste de tous les utilisateurs ou groupes ayant accès à cet objet.  Vous pouvez également attribuer rapidement un nouveau rôle à l'un de ces utilisateurs ou groupes depuis le menu déroulant.

## Définir les Configuration Permissions depuis la vue Utilisateur

Les Configuration Permissions d'un utilisateur peuvent désormais être définies de manière plus conviviale. Depuis la vue Users, toutes les Configuration Permissions sont affichées dans un menu déroulant, puis regroupées par type d'autorisation. Si la sélection des Configuration Permissions diffère de leur valeur actuelle, un bouton « Update Configuration Permissions » s'affiche. Lorsqu'on clique dessus, il est demandé à l'utilisateur de confirmer qu'il souhaite mettre à jour les autorisations du groupe sélectionné avant que la mise à jour ne soit effectuée.

![image](images/pro_user_view.png)
