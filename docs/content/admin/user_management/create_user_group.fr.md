---
title: 'Partager les autorisations : groupes d''utilisateurs'
description: Partager et maintenir les autorisations pour de nombreux utilisateurs
  dans DefectDojo Pro
weight: 3
audience: pro
aliases:
- /fr/en/customize_dojo/user_management/create_user_group
---

> **Fonctionnalité DefectDojo Pro.** Les User Groups et le système RBAC sous-jacent font partie de DefectDojo Pro. DefectDojo Open-Source utilise le modèle [Authorized Users](../os__authorized_users/) — consultez cette page pour le contrôle d'accès en Open-Source, ainsi que les [notes de mise à niveau 3.0](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization) si vous passez d'une édition à l'autre.

Si vous avez un nombre important d'utilisateurs DefectDojo, vous pouvez souhaiter créer un ou plusieurs **Groups**, afin de définir les mêmes règles de contrôle d'accès basé sur les rôles (RBAC) pour de nombreux utilisateurs simultanément. Seuls les Superusers peuvent créer des User Groups.

Les Groups peuvent fonctionner de plusieurs manières :

* Définir un ou plusieurs Roles au niveau Produit ou Type de produit pour tous les Group Members, permettant un contrôle précis des Produits ou Types de produit accessibles et modifiables par le Group.
* Définir un Global Role pour tous les Group Members, leur donnant une visibilité et un accès à tous les Produits ou Types de produit.
* Définir des Configuration Permissions pour un Group, leur permettant de modifier des fonctionnalités spécifiques de DefectDojo.

Pour plus d'informations sur les Roles, veuillez consulter notre article **Introduction aux rôles**.

## La page Tous les groupes

Depuis la barre latérale, accédez à 👤**Utilisateurs \> Groupes** pour voir la liste de tous les groupes d'utilisateurs actifs et inactifs. 

![image](images/Create_a_User_Group_for_shared_permissions.png)
Depuis cet écran, vous pouvez créer, supprimer ou consulter vos pages de Groupe individuelles.

Pour les utilisateurs <span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span>, la page Tous les groupes de l'interface Pro propose quelques options supplémentaires.
* Vous pouvez filtrer ce tableau par nom de groupe, description, adresse e-mail, Global Role, ainsi que par le nombre total d'Utilisateurs, de Types de produit et de Produits associés au Groupe.
* Vous pouvez également ajuster les autorisations d'un Groupe ou d'autres paramètres en cliquant sur le bouton « ⋮ » à côté du Groupe que vous souhaitez modifier.

![image](images/all_groups_pro.png)

## Consulter un groupe

La consultation d'un groupe affiche toutes ses informations : ID, nom, description, Global Role, etc. Les Group Members, Types de produit et Produits associés au groupe sont également affichés. De plus, les Configuration Permissions liées à un Groupe peuvent être mises à jour directement depuis la page « View Group ».

Pour les utilisateurs <span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span>, la vue Groupe de l'interface Pro vous permet d'ajuster les Configuration Permissions d'une manière légèrement différente.

![image](images/group_view_pro_ui.png)

* Toutes les Configuration Permissions sont affichées dans un menu déroulant regroupé en sous-catégories. Si la sélection des Configuration Permissions diffère de leur valeur actuelle, un bouton « Update Configuration Permissions » s'affiche.

![image](images/groups_pro_configuration_permissions.png)

* Une fois quelques autorisations supplémentaires sélectionnées, il sera demandé à l'utilisateur de confirmer qu'il souhaite mettre à jour les autorisations du groupe sélectionné avant que la mise à jour ne soit effectuée.

## Créer / modifier un groupe d'utilisateurs

1. Accédez à la page 👤**Utilisateurs \> Groupes** dans la barre latérale. Vous verrez une liste de tous les groupes d'utilisateurs existants, avec leur nom, description, nombre d'utilisateurs, Global Role (le cas échéant) et e-mail.  
​
![image](images/Create_a_User_Group_for_shared_permissions_2.png)

2. Cliquez sur le **bouton 🛠️** à côté du titre Tous les groupes, puis sélectionnez **\+ Nouveau groupe.**   
​
![image](images/Create_a_User_Group_for_shared_permissions_3.png)
  

3. Vous accédez alors à une page où vous pouvez créer un nouveau Groupe. Définissez le nom de ce Groupe, et ajoutez une description si vous le souhaitez.  
  
Vous pouvez également sélectionner un Global Role que vous souhaitez appliquer à ce Groupe, si vous le désirez. L'ajout d'un Global Role au Groupe donnera à tous les Group Members l'accès à toutes les données DefectDojo, ainsi qu'un accès en modification limité selon le Global Role choisi. Consultez notre article **Introduction aux rôles** pour plus d'informations.

Le compte qui crée initialement un Groupe se voit attribuer par défaut le Role Owner pour ce Groupe.

### Définir une adresse e-mail pour recevoir les rapports

Le Weekly Digest est un rapport portant sur tous les Produits / Types de produit assignés au Groupe. Pour recevoir un Weekly Digest, saisissez l'adresse e-mail de destination que vous souhaitez utiliser dans le formulaire de création/modification du Groupe.  Les membres du Groupe continueront de recevoir les notifications comme d'habitude.

### Consulter la page d'un groupe

Une fois que vous avez créé un Groupe, vous pouvez y accéder en le sélectionnant dans le menu **Utilisateurs \> Groupes.**

La page du Groupe peut être personnalisée avec une **Description**. Elle affiche la liste de tous les **Group Members**, ainsi que les **Produits** et **Types de produit** attribués, et le **Role** associé à chacun d'eux**.**

Vous pouvez également y consulter les **Configuration Permissions** du Groupe.

## Gérer les utilisateurs d'un groupe

Le Group Membership se gère depuis la page individuelle du Groupe, accessible depuis la liste de la page **Utilisateurs \> Groupes**. Cliquez sur le nom du Groupe en surbrillance pour accéder à la page du Groupe que vous souhaitez modifier.

Pour consulter ou modifier le Membership d'un Groupe, un User doit disposer des Configuration Permissions appropriées activées ainsi que d'un Membership dans le Groupe (ou du statut Superuser).

### **Ajouter un utilisateur à un groupe**

Les User Groups peuvent avoir autant d'Users assignés que vous le souhaitez. Tous les Users d'un Groupe se voient attribuer le Role associé à chaque Produit ou Type de produit listé, mais les Users peuvent également avoir des Roles individuels qui priment sur le Role du Groupe.

1. Depuis la page du Groupe, sélectionnez **\+ Add Users** dans le bouton **☰** situé au bord du titre **Members**.  
​
![image](images/Create_a_User_Group_for_shared_permissions_4.png)

2. Vous accédez alors à l'écran **Add Some Group Members**. Ouvrez le menu déroulant Users, puis cochez chaque utilisateur que vous souhaitez ajouter au Groupe.  
​
![image](images/Create_a_User_Group_for_shared_permissions_5.png)

3. Sélectionnez le Group Role que vous souhaitez attribuer à ces Users. Cela détermine leur capacité à configurer le Groupe.

Notez que l'ajout d'un membre à un Groupe ne lui donne pas accès par défaut à sa propre page de Groupe. Il s'agit d'une Configuration Permission distincte qui doit être activée au préalable.

### **Modifier ou supprimer un membre d'un groupe d'utilisateurs**

1. Depuis la page du Groupe, sélectionnez le ⋮ à côté du nom de l'User que vous souhaitez modifier ou supprimer du Groupe.  

**📝 Edit** vous amène à l'écran Edit Member, où vous pouvez modifier le Role de cet utilisateur (de Reader, Maintainer ou Owner vers un autre choix).  

**🗑️ Delete** supprime entièrement le Membership de l'User. Cela ne supprime pas les contributions ou modifications que l'User a apportées au Produit ou au Type de produit.

![image](images/Create_a_User_Group_for_shared_permissions_6.png) 

## Gérer les autorisations d'un groupe

Les Group Permissions se gèrent depuis la page individuelle du Groupe, accessible depuis la liste de la page **Utilisateurs \> Groupes**. Cliquez sur le nom du Groupe en surbrillance pour accéder à la page du Groupe que vous souhaitez modifier.

Notez que seuls les Superusers peuvent modifier les autorisations d'un Groupe (Produit / Type de produit, ou Configuration).  
​
### **Ajouter des Roles Produit ou des Roles Type de produit pour un groupe**

Vous pouvez enregistrer autant de Roles Produit ou de Roles Type de produit que vous le souhaitez dans chaque Groupe.

1. Depuis la page du Groupe, sélectionnez **\+ Add Product Types**, ou \+ **Add Product** dans le titre correspondant (Product Type Groups ou Product Groups).  
​
![image](images/Create_a_User_Group_for_shared_permissions_7.png)

2. Vous accédez alors à une page **Register New Products / Product Types**, où vous pouvez sélectionner dans le menu déroulant un Produit ou un Type de produit à ajouter.

![image](images/Create_a_User_Group_for_shared_permissions_8.png)

3. Sélectionnez le Role que vous souhaitez que tous les membres du Groupe possèdent pour ce Produit ou ce Type de produit en particulier.

Les Groupes ne peuvent pas être affectés à des Produits ou des Types de produit sans Role. Si vous ne savez pas quel Role attribuer à un Groupe, Reader constitue une bonne option « par défaut ». Cela permet de garder votre Produit sécurisé en attendant votre décision finale concernant le Group Role.

### **Attribuer des Configuration Permissions à un groupe**

Si vous souhaitez que les Members de votre Groupe accèdent aux fonctions de Configuration et contrôlent certains aspects de DefectDojo, vous pouvez attribuer ces responsabilités depuis la page du Groupe. 

Attribuez les rôles View, Add, Edit ou Delete depuis le menu situé dans le coin inférieur droit. Cocher une Configuration Permission donne immédiatement au Groupe l'accès à cette fonction particulière.

![image](images/Create_a_User_Group_for_shared_permissions_9.png)
