---
title: "Azure DevOps"
description: "Comment configurer le Connecteur Upstream Azure DevOps pour DefectDojo"
weight: 20
audience: pro
---
Le connecteur Azure DevOps est un **Connecteur d'actifs** : il énumère les dépôts git de chaque projet de votre organisation Azure DevOps et crée un Actif DefectDojo pour chaque dépôt, regroupé en Organisations par projet Azure DevOps. Aucune constatation n'est importée.

#### Prérequis

Vous aurez besoin d'un jeton d'accès personnel (PAT) pour l'organisation. Nous recommandons de générer ce jeton depuis un compte de service dédié. Seuls des scopes en lecture sont nécessaires :

1. Dans Azure DevOps, ouvrez **User settings \> Personal access tokens \> New Token**.
2. Cliquez sur **Show all scopes**, puis sélectionnez **Code: Read** et **Project and Team: Read**.

Seul Azure DevOps Services (dev.azure.com) est pris en charge ; Azure DevOps Server sur site n'est pas pris en charge pour le moment.

#### Mappages du Connecteur

1. Saisissez l'URL de votre organisation dans le champ **Location** : `https://dev.azure.com/{your-organization}`. Les URL héritées `https://{your-organization}.visualstudio.com` sont également acceptées, et tout segment de chemin supplémentaire (par exemple, un lien vers un projet spécifique) est ignoré.
2. Saisissez le PAT dans le champ **Secret**.

Chaque dépôt devient un Enregistrement portant le nom du dépôt, regroupé par **projet** Azure DevOps. Les dépôts désactivés sont ignorés, si bien que désactiver ou supprimer un dépôt marque son Enregistrement comme `MISSING` lors de la prochaine synchronisation.
