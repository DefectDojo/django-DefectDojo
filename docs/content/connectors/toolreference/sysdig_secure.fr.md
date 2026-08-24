---
title: "Sysdig Secure"
description: "Comment configurer le Connecteur Upstream Sysdig Secure pour DefectDojo"
weight: 130
audience: pro
---
Le connecteur Sysdig Secure importe des **constatations de vulnérabilité de conteneurs / CNAPP** depuis l'API de gestion des vulnérabilités de Sysdig Secure. Il synchronise l'intégralité du compte sur le ou les périmètres configurés et crée un produit DefectDojo pour chaque regroupement d'actifs analysé.

#### Prérequis

Un **jeton API** Sysdig Secure : dans Sysdig Secure, allez dans **Settings > Sysdig Secure API Token** et copiez le jeton. Vous avez également besoin de l'**URL de région** Sysdig (par exemple `https://us2.app.sysdig.com`, `https://eu1.app.sysdig.com`, ou votre hôte sur site).

#### Mappages du connecteur

1. Saisissez votre région/URL de base Sysdig dans le champ **Location**.
2. Saisissez le jeton API dans le champ **Secret**.
3. Optionnellement, définissez **Scopes** — une liste séparée par des virgules de `runtime`, `registry` et/ou `pipeline` (laissez vide pour `runtime`, le périmètre des charges de travail déployées).
4. Optionnellement, définissez **Runtime Product Grouping** — la façon dont les résultats runtime sont associés aux produits : `cluster`, `namespace`, `workload` ou `image` (laissez vide pour `namespace`). Les résultats registry et pipeline sont toujours regroupés par dépôt d'images.
5. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations importées.

Chaque regroupement d'actifs devient un Enregistrement. Pour chaque résultat de scan, le connecteur importe chaque paquet vulnérable comme constatation. Les constatations **Runtime** (charges de travail déployées) sont enregistrées comme des constatations dynamiques et étiquetées avec leur contexte Kubernetes cluster / namespace / workload / conteneur ; les constatations **registry** et **pipeline** sont enregistrées comme des constatations statiques d'analyse d'image. La sévérité `NEGLIGIBLE` de Sysdig est associée à Info.
