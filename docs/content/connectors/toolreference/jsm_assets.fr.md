---
title: "Jira Service Management Assets"
description: "Comment configurer le Connecteur Upstream Jira Service Management Assets pour DefectDojo"
weight: 83
audience: pro
---
Le connecteur JSM Assets est un **Connecteur d'actifs** : il énumère les objets de votre espace de travail Jira Service Management Assets (anciennement Insight) et crée un Actif DefectDojo pour chaque objet, regroupés en Organisations par schéma d'objet. Aucune constatation n'est importée.

#### Prérequis

* Assets nécessite un plan **Jira Service Management Premium ou Enterprise**. Sur les plans Free ou Standard, l'API Assets répond avec `403 "Access to Assets API was denied"`, même si le reste du site fonctionne.
* Le compte Atlassian utilisé doit disposer d'un **accès produit Jira Service Management** (un siège agent) sur le site — l'accès au site seul ne suffit pas.
* Créez un jeton API Atlassian classique sur [id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens). Nous recommandons un compte de service dédié.

#### Mappages du connecteur

1. Saisissez l'URL de votre site Atlassian dans le champ **Location** : `https://{your-site}.atlassian.net`.
2. Saisissez l'e-mail du compte Atlassian auquel appartient le jeton dans le champ **Email**.
3. Saisissez le jeton API dans le champ **Secret**.

Chaque objet Assets devient un Enregistrement nommé d'après le libellé de l'objet, regroupé par son **schéma d'objet**.
