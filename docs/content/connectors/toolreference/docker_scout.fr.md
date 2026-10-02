---
title: "Docker Scout"
description: "Comment configurer le Connecteur Upstream Docker Scout pour DefectDojo"
weight: 50
audience: pro
---
Le connecteur Docker Scout utilise l'API de l'exportateur de métriques Docker Scout pour rendre compte de la posture de vulnérabilité des images de votre organisation. DefectDojo découvre chaque flux (stream) Docker Scout (vos environnements d'exécution) et importe un résumé des vulnérabilités et de la conformité aux politiques pour chacun.

#### Prérequis

Vous aurez besoin d'un jeton d'accès personnel Docker créé par un **owner** d'une organisation Docker **inscrite à Docker Scout**. L'exportateur de métriques est une fonctionnalité au niveau de l'organisation ; un compte personnel, ou une organisation non inscrite à Docker Scout, ne renverra donc aucune donnée.

Créez le jeton depuis les paramètres de votre compte Docker, sous **Personal access tokens**, et notez votre **espace de noms d'organisation** Docker, qui vous sera également nécessaire.

#### Mappages du connecteur

1. Saisissez `https://api.scout.docker.com` dans le champ **Location**.
2. Saisissez votre jeton d'accès personnel Docker dans le champ **Secret**.
3. Saisissez votre espace de noms **Organization** Docker.
4. Facultativement, définissez une **Minimum Severity** pour limiter les constatations importées. Les constatations d'une sévérité inférieure à celle sélectionnée ne seront pas importées.

DefectDojo crée un enregistrement distinct pour chaque flux Docker Scout, et importe une constatation par sévérité pour les vulnérabilités que Docker Scout comptabilise dans ce flux, ainsi qu'une constatation pour chaque image qui échoue à votre politique Docker Scout. L'API de métriques de Docker Scout renvoie des comptages agrégés plutôt que des CVE individuels ; ces constatations résument donc la posture d'un flux. Ouvrez le flux dans Docker Scout pour obtenir le détail par image et par CVE.

Pour plus d'informations, consultez la [documentation Docker Scout](https://docs.docker.com/scout/).
