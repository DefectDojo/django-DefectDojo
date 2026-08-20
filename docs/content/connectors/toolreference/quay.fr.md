---
title: "Quay"
description: "Comment configurer le Connecteur Upstream Quay pour DefectDojo"
weight: 110
audience: pro
---
Le connecteur Quay utilise l'API REST de Project Quay pour découvrir les dépôts de conteneurs et importer les rapports de vulnérabilités produits par le scanner **Clair** intégré à Quay. DefectDojo crée un Record pour chaque **dépôt** Quay et, à chaque Sync, lit le rapport de sécurité Clair du manifeste d'image de chaque tag actif.

#### Prérequis

Le scan de sécurité (Clair) doit être activé sur votre instance Quay, et vous aurez besoin d'un **jeton d'accès OAuth 2** Quay :

* Dans Quay, créez (ou ouvrez) une organisation, allez dans **Applications**, créez une application OAuth, puis **Generate Token** avec au minimum le scope **Read repositories**. Une application dédiée pour DefectDojo est recommandée.
* Le jeton est envoyé comme jeton Bearer à chaque requête et n'est jamais journalisé.

#### Correspondances du connecteur

1. Saisissez l'URL de base de votre Quay dans le champ **Location**, par exemple `https://quay.io` ou votre instance auto\-hébergée `https://quay.example.com`. L'URL doit être en HTTPS ; n'incluez pas de chemin d'API final — DefectDojo construit automatiquement les chemins d'API.
2. Saisissez le jeton d'accès OAuth dans le champ **Secret**.
3. Optionnellement, définissez un **Namespace** pour restreindre la découverte à une seule organisation ou un seul utilisateur Quay. Laissez vide pour découvrir tous les dépôts que le jeton peut lire.
4. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations importées.

DefectDojo associe chaque **dépôt** Quay à un Record. Pour chaque dépôt, il liste les tags actifs, les déduplique vers leurs manifestes d'image uniques (un manifeste partagé par plusieurs tags est scanné une seule fois), et lit le rapport Clair de chaque manifeste. Les manifestes que Clair n'a pas terminé de scanner (par exemple une liste de manifestes multi\-architecture, ou une image encore en file d'attente) sont ignorés jusqu'à un Sync ultérieur. Chaque vulnérabilité Clair devient une constatation — le paquet concerné est le composant, la version corrigée devient la mitigation, et les sévérités **Negligible**/**Unknown** de Clair sont enregistrées comme **Informational**.

Consultez la [documentation de l'API Project Quay](https://docs.projectquay.io/api_quay.html) et la [documentation Clair](https://quay.github.io/clair/) pour plus d'informations.
