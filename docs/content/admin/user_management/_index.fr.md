---
title: Gestion des utilisateurs
description: Gérer les utilisateurs, le contrôle d'accès et l'authentification dans
  DefectDojo
summary: ''
date: 2023-09-07 16:06:50+02:00
lastmod: 2023-09-07 16:06:50+02:00
draft: false
weight: 5
chapter: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
exclude_search: true
---

La gestion des utilisateurs de DefectDojo diffère selon l'édition. Choisissez la section correspondant à votre installation.

## DefectDojo Open-Source

DefectDojo Open-Source utilise le modèle **Authorized Users** : un utilisateur obtient l'accès à un Produit ou à un Type de produit en étant ajouté à la liste des Authorized Users de cet enregistrement. Les Superusers et le personnel (staff) voient tout.

* [Authorized Users](./os__authorized_users/) — comment accorder l'accès aux Produits et aux Types de produit

L'authentification sur DefectDojo Open-Source repose sur un identifiant/mot de passe local, complété par le flux de réinitialisation du mot de passe.

## DefectDojo Pro

DefectDojo Pro utilise un système basé sur les rôles avec des Members, des Groups et des Global Roles. Les utilisateurs peuvent également se voir accorder un accès SSO via SAML ou l'un des fournisseurs OAuth pris en charge.

* [Autorisations dans DefectDojo](./about_perms_and_roles/) — présentation des Roles, Memberships, Global Roles et Configuration Permissions
* [Définir les autorisations d'un utilisateur](./set_user_permissions/) — attribution des Roles, Global Roles et Configuration Permissions
* [Partager les autorisations : groupes d'utilisateurs](./create_user_group/) — attribution des autorisations à de nombreux utilisateurs à la fois
* [Définir les autorisations dans Pro](./pro_permissions_overhaul/) — interface spécifique à Pro pour gérer les Members et les Permissions
* [Réinitialisation groupée des identifiants utilisateur](./pro__resetting_user_credentials/) — faire pivoter les jetons API et forcer la réinitialisation des mots de passe pour de nombreux utilisateurs à la fois
* [Tableaux des autorisations par action](./user_permission_chart/) — référence complète de chaque autorisation pour chaque rôle intégré
* [Rôles RBAC personnalisés](./pro__custom_rbac_roles/) — créez vos propres rôles en choisissant des autorisations individuelles
* [Authentification unique (SSO)](/admin/sso/) — configuration SAML et OAuth pour Pro

## Migration entre éditions

Si vous passez du modèle Authorized Users de l'Open-Source au RBAC de Pro, ou si vous effectuez une mise à niveau depuis une version Open-Source antérieure à 3.0 qui utilisait le RBAC vers le modèle Authorized Users actuel, consultez les [notes de mise à niveau 3.0](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization). L'accès existant est conservé automatiquement.
