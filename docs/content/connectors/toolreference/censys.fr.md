---
title: "Censys"
description: "Comment configurer le Connecteur Upstream Censys pour DefectDojo"
weight: 32
audience: pro
---
Le connecteur Censys lit les actifs de type host depuis la Censys Platform et importe les services exposés de chaque host sous forme de constatations. Il utilise l'API de recherche globale de la Censys Platform pour énumérer les hosts sur lesquels vous le limitez.

#### Prérequis

Vous aurez besoin d'un compte Censys **Platform** avec accès API :

* Un **Personal Access Token**, créé dans la Censys Platform Console sous Personal Access Tokens.
* Votre **Organization ID**, affiché sur la même page de paramètres sous « Current Organization ». L'accès API au point de terminaison de recherche nécessite une organisation ; un abonnement Starter ou supérieur est donc requis. Les jetons de niveau gratuit n'ont pas d'Organization ID et ne peuvent pas utiliser l'API de recherche.

Les données de CVE et de risque par host ne sont disponibles que sur les abonnements Censys Core (entreprise) ; sur les niveaux inférieurs, les constatations représentent donc des services exposés plutôt que des vulnérabilités.

Consultez la [documentation de l'API Censys Platform](https://docs.censys.com/reference/get-started) pour plus d'informations.

#### Mappages du Connecteur

1. Saisissez `https://api.platform.censys.io` dans le champ **Location**.
2. Saisissez votre Personal Access Token dans le champ **API Key**.
3. Saisissez votre **Organization ID**.
4. Saisissez une **Search Query** qui limite l'import à vos propres actifs, par exemple `host.autonomous_system.asn: <your ASN>` ou `host.ip: 203.0.113.0/24`.
5. Facultativement, définissez une **Minimum Severity** pour limiter les constatations importées.

DefectDojo crée un Enregistrement pour chaque host et importe ses services exposés sous forme de constatations.
