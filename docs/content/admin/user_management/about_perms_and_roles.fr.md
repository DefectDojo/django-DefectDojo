---
title: Autorisations dans DefectDojo
description: Résumé détaillé de toutes les options d'autorisation de DefectDojo Pro
weight: 2
audience: pro
aliases:
- /fr/en/customize_dojo/user_management/about_perms_and_roles
---

> **Fonctionnalité DefectDojo Pro.** Le système RBAC Members / Groups / Global Roles décrit sur cette page fait partie de DefectDojo Pro. DefectDojo Open-Source utilise le modèle [Authorized Users](../os__authorized_users/) — consultez cette page pour le contrôle d'accès en Open-Source, ainsi que les [notes de mise à niveau 3.0](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization) si vous passez d'une édition à l'autre.

Si vous avez une équipe d'utilisateurs travaillant dans DefectDojo, il est important de configurer correctement le contrôle d'accès basé sur les rôles (Role-Based Access Control, RBAC) afin que les utilisateurs n'accèdent qu'à des données spécifiques. Les données de sécurité sont hautement sensibles, et les options de contrôle d'accès de DefectDojo vous permettent de définir précisément l'accès de chaque membre de l'équipe à l'information.

Cet article donne une vue d'ensemble du fonctionnement des autorisations dans DefectDojo. Si vous préférez consulter une répartition détaillée de **chaque action** pouvant être contrôlée par les autorisations, consultez notre article **[Tableau des autorisations](../user_permission_chart/)**.

## Types d'autorisations

DefectDojo gère quatre types d'autorisations différents :

* Les utilisateurs peuvent être affectés comme **Members** à des **Produits ou des Types de produit**. Un Membership sur un Produit s'accompagne d'un **Role** qui permet à vos utilisateurs de consulter et d'interagir avec les types de données (Types de produit, Produits, Engagements, Tests et Constatations) dans DefectDojo. Les utilisateurs peuvent avoir plusieurs memberships sur des Produits ou des Types de produit, avec différents niveaux d'accès.  
​
* Les utilisateurs peuvent également se voir attribuer des **Configuration Permissions**, qui leur permettent d'accéder aux pages de configuration de DefectDojo. Les Configuration Permissions ne sont pas liées aux Produits ou aux Types de produit, et ne sont pas associées à des Roles.  
​
* Les utilisateurs peuvent se voir attribuer des **Global Roles**, qui leur donnent un niveau d'accès standardisé à tous les Produits et Types de produit.  
​
* Les utilisateurs peuvent être configurés comme **Superusers** : des rôles de niveau administrateur qui leur donnent le contrôle et l'accès à toutes les données et à la configuration de DefectDojo.

Chacun de ces types d'autorisation peut également être attribué à un **Group** d'**Users**. Si vous avez un grand nombre d'utilisateurs dans DefectDojo, comme une équipe de test dédiée à un Produit particulier, les Groups vous permettent de configurer et de maintenir les autorisations rapidement.

## Membership Produit/Type de produit et Roles

Lorsque des utilisateurs sont affectés comme membres à un Produit ou à un Type de produit, ils reçoivent également un rôle qui détermine comment ils interagissent avec les données de Constatation associées.

### Résumé des rôles

DefectDojo Pro est livré avec cinq **rôles intégrés** : Reader, Writer, Maintainer, Owner et API Importer. Chacun d'eux peut être attribué globalement ou au sein d'un Produit / Type de produit.

Les rôles intégrés sont des préréglages verrouillés. Ils ne peuvent être ni modifiés ni supprimés, et leurs autorisations sont identiques sur chaque instance de DefectDojo Pro. Si aucun d'eux ne correspond au fonctionnement de votre équipe, vous pouvez en créer un qui convient, en choisissant des autorisations individuelles ou en clonant un rôle intégré et en l'ajustant. Voir [Rôles RBAC personnalisés](../pro__custom_rbac_roles/).

Les « données sous-jacentes » désignent l'ensemble des Produits, Engagements, Tests, Constatations ou Points de terminaison rattachés à un Produit ou à un Type de produit.

* Les **utilisateurs Reader** peuvent consulter les données sous-jacentes de tout Produit ou Type de produit auquel ils sont affectés, et ajouter des commentaires. Ils ne peuvent ni modifier, ni ajouter, ni altérer d'aucune autre façon les données sous-jacentes, mais ils peuvent exporter des Rapports et ajouter des Notes aux données.  
​
* Les **utilisateurs Writer** disposent de toutes les capacités Reader, plus la possibilité d'ajouter ou de modifier des Engagements, des Tests et des Constatations. Ils ne peuvent pas ajouter de nouveaux Produits, ni supprimer de données sous-jacentes.  
​
* Les **utilisateurs Maintainer** disposent de toutes les capacités Writer, plus la possibilité de modifier le Produit ou le Type de produit. Ils peuvent ajouter de nouveaux Members avec des Roles au Produit ou au Type de produit, et peuvent également supprimer des Engagements, des Tests et des Constatations.  
​
* Les **utilisateurs Owner** disposent du plus grand contrôle sur un Produit ou un Type de produit. Ils peuvent désigner d'autres Owners, et peuvent également supprimer les Produits ou Types de produit auxquels ils sont affectés.  
​
* Les utilisateurs **API Importer** disposent de capacités limitées. Ce Role permet un accès API restreint sans exposer la majorité des points de terminaison de l'API ; il est donc utile pour l'automatisation ou pour les utilisateurs censés rester « externes » à DefectDojo. Ils peuvent consulter les données sous-jacentes, ajouter/modifier des Engagements, et importer des données de scan.

Pour des informations détaillées sur les rôles intégrés, consultez notre **[Tableau des autorisations par rôle](../user_permission_chart/)**. Pour la liste complète des autorisations pouvant être attribuées à un rôle, et pour savoir comment créer le vôtre, consultez **[Rôles RBAC personnalisés](../pro__custom_rbac_roles/)**.

### Global Roles

Les utilisateurs disposant de **Global Roles** peuvent consulter et interagir avec tout type de données (Types de produit, Produits, Engagements, Tests et Constatations) dans DefectDojo, en fonction du Role qui leur est attribué.

### Group Memberships

Les User Groups peuvent être ajoutés comme Members d'un Produit ou d'un Type de produit. Les utilisateurs faisant partie du Group héritent de l'accès à tous les Produits ou Types de produit associés, ainsi que du Role attribué au Group.

#### Utilisateurs disposant de plusieurs rôles

* Si un User est affecté comme membre d'un Produit, il ne reçoit par défaut aucune autorisation associée au Type de produit.

* Si un User se retrouve avec plusieurs rôles sur le même Produit ou Type de produit (par exemple un attribué directement et un autre hérité d'un Group), il reçoit les autorisations **combinées** de tous les rôles qu'il détient à cet endroit.

* Le Role Produit d'un User prime toujours sur son Role Type de produit « par défaut ».  
​
* Le Role Produit / Type de produit d'un User prime toujours sur son Global Role au sein du Produit ou Type de produit sous-jacent. Par exemple, si un User a un Role Type de produit Reader, mais est également affecté comme Owner sur un Produit rattaché à ce Type de produit, il obtiendra des autorisations Owner supplémentaires uniquement pour ce Produit.  
​
* Les Roles ne peuvent pas retirer d'autorisations, ils ne peuvent qu'en ajouter. Par exemple, si un User a un Role Type de produit ou un Global Role Owner, lui attribuer un rôle Reader sur un Produit particulier ne lui retirera pas ses autorisations Owner sur ce Produit.  
​
* Le statut Superuser prime toujours sur les Roles attribués.

## Superusers

Les Superusers (Admins) n'ont aucune limitation dans le système. Ils peuvent modifier tous les paramètres, gérer les utilisateurs et disposent d'un accès en lecture/écriture à toutes les données. Ils peuvent également modifier les règles d'accès de tous les utilisateurs de DefectDojo. Les Superusers reçoivent également les notifications pour tous les problèmes et alertes système.

Par défaut, le premier compte créé sur une nouvelle instance DefectDojo dispose des autorisations Superuser. Cet utilisateur pourra modifier les autorisations de tous les utilisateurs DefectDojo créés par la suite. Seul un Superuser existant peut ajouter un autre superuser, ou attribuer un Global Role à un utilisateur. 


## Configuration Permissions

Les Configuration Permissions, bien que similaires, ne sont pas liées aux Produits ou aux Roles. Elles doivent être attribuées séparément des Roles. **Les utilisateurs standards n'ont aucune Configuration Permission par défaut, et l'attribution de ces autorisations de configuration doit se faire avec prudence.**

Les utilisateurs peuvent se voir attribuer des Configuration Permissions de différentes manières :

1. Les Configuration Permissions peuvent être attribuées directement aux utilisateurs. Des autorisations spécifiques peuvent être configurées directement sur une page User.  

2. Des Configuration Permissions peuvent être attribuées aux User Groups. Comme pour les Roles, des Configuration Permissions spécifiques peuvent être ajoutées aux Groups, ce qui donnera ces autorisations à tous les membres du Group.

Les Superusers disposent de toutes les Configuration Permissions, ils n'ont donc pas de section Configuration Permission sur leur page User.

### Group Configuration Permissions

Si des utilisateurs font partie d'un Group, ils disposent également de Group Configuration Permissions qui contrôlent leur niveau d'accès à la configuration du Group. Les Group Permissions ne correspondent pas au membership du Group sur un Produit ou un Type de produit.

Si des utilisateurs créent un nouveau Group, ils se voient attribuer par défaut le rôle Owner de ce nouveau Group.

Pour plus d'informations sur les Configuration Permissions, consultez notre **[Tableau des Configuration Permissions](../user_permission_chart/#configuration-permission-chart)**.

## Gérer les autorisations par défaut

Lorsqu'un tout nouvel utilisateur est créé dans DefectDojo — que ce soit manuellement, via SAML / SSO, ou via un fournisseur social-auth — il **ne dispose d'aucune autorisation par défaut**. Il ne verra aucun Type de produit, aucun Produit et aucun Engagement lors de sa première connexion. Il ne peut consulter ni interagir avec aucune donnée tant qu'un Superuser ne lui a pas accordé l'accès (directement, via un Global Role, via un membership Produit / Type de produit, ou en l'ajoutant à un Group).

Si vous souhaitez que chaque nouvel utilisateur provisionné reçoive automatiquement un niveau d'accès de base — par exemple, « chaque nouvel utilisateur SSO doit être Reader sur un groupe particulier » — vous pouvez configurer un **Default group** sur la page System Settings.

1. Ouvrez **⚙️ Configuration → System Settings** (réservé aux Superusers).
2. Définissez **Default group** sur le [User Group](../create_user_group/) que les utilisateurs nouvellement créés doivent rejoindre.
3. Définissez **Default group role** sur le rôle qu'ils doivent détenir dans ce groupe (par exemple **Reader**).
4. Définissez éventuellement **Default group email pattern** avec une expression régulière (par exemple `.*@yourcompany\.com$`) afin que le groupe par défaut ne s'applique qu'aux utilisateurs dont l'e-mail correspond.
5. Enregistrez.

**Default group** et **Default group role** doivent tous deux être définis — si l'un des deux est vide, le groupe par défaut n'est pas appliqué.

Ce paramètre s'applique à tous les chemins de création d'utilisateur : création manuelle, SAML, OAuth et autres fournisseurs social-auth. Il n'est pas appliqué rétroactivement — les utilisateurs existants conservent leurs memberships de groupe actuels même si vous modifiez ce paramètre ultérieurement.

Pour des conseils spécifiques au SSO, consultez [Configuration SAML](/admin/sso/pro__saml/#default-access-for-sso-provisioned-users) ou la section de votre fournisseur sous [Configuration SSO](../configure_sso/).
