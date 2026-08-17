---
title: Permissions Open Source
description: Comment l'accès aux Produits et Types de produit est accordé dans DefectDojo
  open source
weight: 1
audience: opensource
---

DefectDojo open source contrôle l'accès aux Produits et Types de produit à l'aide du modèle **Authorized Users**. Chaque Produit et Type de produit dispose d'un panneau Authorized Users répertoriant les personnes pouvant voir cet enregistrement et les données qui y sont imbriquées.

Si vous utilisez DefectDojo Pro, cet article ne s'applique pas à votre installation — Pro utilise un système de rôles plus riche, décrit dans [Autorisations dans DefectDojo](../about_perms_and_roles/).

## Comment l'accès est accordé

Il existe deux listes, et un utilisateur n'a besoin de figurer que sur l'une d'elles pour obtenir l'accès :

- **La liste Authorized Users d'un Produit** accorde l'accès à ce Produit unique, ainsi qu'à tout ce qui est imbriqué en dessous (ses Engagements, Tests, Constatations et Points de terminaison).
- **La liste Authorized Users d'un Type de produit** accorde l'accès au Type de produit lui-même **et se répercute sur chaque Produit qui en dépend**. Un utilisateur autorisé sur un Type de produit n'a pas besoin d'être également ajouté à chaque Produit enfant — il est déjà couvert.

Il n'y a ni rôles, ni groupes, ni rôles globaux. Un utilisateur est soit sur la liste (ou est superuser/membre du staff — voir ci-dessous), soit il ne peut pas voir le Produit.

## Les superusers et le staff contournent les listes

Les utilisateurs marqués comme **superuser** ou **staff** dans DefectDojo peuvent voir et agir sur chaque Produit et Type de produit indépendamment des listes Authorized Users. Ces listes existent pour accorder l'accès aux utilisateurs qui ne sont pas membres du staff ; elles ne restreignent ni le staff ni les superusers.

Le premier compte créé sur une installation DefectDojo neuve est automatiquement superuser.

## Qui peut modifier les listes

Seuls les utilisateurs **superuser** ou **staff** voient les contrôles permettant d'ajouter ou de retirer des personnes d'un panneau Authorized Users. Toute autre personne ayant accès à un Produit ou un Type de produit voit le panneau comme une liste en lecture seule — utile pour savoir qui d'autre fait partie de l'équipe, mais pas pour modifier l'appartenance.

## Où se trouve le panneau

Le panneau Authorized Users apparaît sur deux pages de l'interface classique :

- La **page de détail du Produit** dispose d'un panneau Authorized Users pour ce Produit. Elle prend en charge deux actions pour les utilisateurs staff :
  - **Ajouter un utilisateur à la liste Authorized Users du Produit**
  - **Retirer un utilisateur de la liste Authorized Users du Produit**
- La **page de détail du Type de produit** dispose d'un panneau Authorized Users pour ce Type de produit, avec les deux actions correspondantes :
  - **Ajouter un utilisateur à la liste Authorized Users du Type de produit**
  - **Retirer un utilisateur de la liste Authorized Users du Type de produit**

Lorsque vous retirez un utilisateur de la liste d'un Type de produit, la répercussion est également supprimée — il perd l'accès à chaque Produit enfant, sauf s'il figure encore sur la liste d'un Produit spécifique, ou s'il est staff/superuser.

## Choisir entre un accès au niveau Produit ou Type de produit

Quelques règles empiriques :

- Si une personne doit voir tous les Produits d'une catégorie (par exemple, tous les Produits possédés par une équipe donnée), placez-la sur la liste du **Type de produit** et laissez la répercussion faire le reste.
- Si une personne ne doit voir qu'un seul Produit spécifique, placez-la sur la liste de ce **Produit**.
- Si vous vous retrouvez à ajouter la même personne à de nombreux Produits individuels sous un même Type de produit, c'est le signe que vous devriez plutôt l'ajouter au Type de produit.

## En provenance d'une version antérieure de DefectDojo

DefectDojo open source est revenu au modèle Authorized Users dans la version 3.0. Si vous effectuez une mise à niveau depuis une version qui utilisait le système Members / Groups / Global Roles, votre accès existant est automatiquement reporté vers Authorized Users par la mise à niveau — aucune correspondance manuelle n'est nécessaire.

La mise à niveau est livrée avec une commande de gestion en lecture seule, `preview_legacy_authorization_migration`, qui résume ce que la mise à niveau changerait, à partir d'une copie de votre base de données. Le flux recommandé consiste à installer la 3.0 dans un environnement de staging avec un instantané de la production, à exécuter la commande, à examiner le résumé, puis à mettre à niveau la production.

Si vous allez dans l'autre sens — d'open source vers DefectDojo Pro — Pro est livré avec une commande `reconcile_authorized_users_to_rbac` qui reporte l'accès Authorized Users vers le RBAC de Pro. Elle prend en charge `--dry-run` et est idempotente.

Pour plus de détails sur les deux parcours, consultez les [notes de mise à niveau 3.0](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization).
