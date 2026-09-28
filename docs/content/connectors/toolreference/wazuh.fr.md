---
title: "Wazuh"
description: "Comment configurer le Connecteur Upstream Wazuh pour DefectDojo"
weight: 140
audience: pro
---
Le connecteur Wazuh utilise le Wazuh Indexer (OpenSearch) pour récupérer les constatations de vulnérabilité. Wazuh 4.8 et versions ultérieures stockent les CVE détectées dans l'Indexer plutôt que dans l'API du serveur Wazuh ; ce connecteur les lit donc directement dans l'index `wazuh-states-vulnerabilities-*`.

DefectDojo crée un Enregistrement pour chaque agent Wazuh (point de terminaison) et importe les CVE détectées par cet agent comme constatations selon une planification.

#### Prérequis

Vous aurez besoin de :

* L'URL de base de votre Wazuh Indexer, port inclus (l'Indexer écoute par défaut sur le port 9200). DefectDojo se connecte directement à l'Indexer, ce point de terminaison doit donc être accessible depuis DefectDojo. Pour les déploiements auto-gérés, il s'agit de l'hôte exécutant le Wazuh Indexer. Pour Wazuh Cloud, utilisez le point de terminaison de l'Indexer indiqué dans votre console Wazuh Cloud, distinct de l'URL du tableau de bord Wazuh.
* Un utilisateur et un mot de passe Indexer disposant d'un accès en lecture à l'index `wazuh-states-vulnerabilities-*`. Nous recommandons de créer un utilisateur dédié pour DefectDojo.

La détection de vulnérabilités doit être activée dans Wazuh pour que l'index d'état des vulnérabilités soit alimenté. Consultez la [documentation de détection de vulnérabilités de Wazuh](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/index.html) pour plus d'informations.

#### Mappages du connecteur

1. Saisissez l'URL de base de votre Wazuh Indexer dans le champ **Location**, avec le schéma et le port, par exemple `https://your-indexer.example.com:9200`. N'incluez pas de chemin final. DefectDojo construit automatiquement les chemins de recherche.
2. Saisissez le nom d'utilisateur de l'Indexer dans le champ **Username**.
3. Saisissez le mot de passe de l'Indexer dans le champ **Password**.
4. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations importées. Les constatations en dessous de la sévérité sélectionnée ne seront pas importées.
