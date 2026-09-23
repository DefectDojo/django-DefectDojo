---
title: "Kubescape"
description: "Comment configurer le Connecteur Upstream Kubescape pour DefectDojo"
weight: 85
audience: pro
---
Le connecteur Kubescape lit les résultats de posture Kubernetes (mauvaises configurations) produits par l'[opérateur Kubescape](https://kubescape.io/docs/install-operator/) directement depuis l'API Kubernetes du cluster — aucun compte SaaS ARMO n'est requis. Il lit les objets `WorkloadConfigurationScan` servis par l'API agrégée de stockage in-cluster de l'opérateur (`spdx.softwarecomposition.kubescape.io/v1beta1`). Chaque **espace de noms** Kubernetes disposant de résultats de posture est mappé à un Enregistrement (Produit) ; chaque contrôle échoué sur une charge de travail devient une Constatation.

#### Prérequis

- L'opérateur Kubescape doit être installé dans le cluster cible avec l'analyse de configuration activée (voir [Installing in your cluster](https://kubescape.io/docs/install-operator/)). Confirmez l'existence de résultats avec `kubectl get workloadconfigurationscans -A`.
- Un **kubeconfig** accordant un accès en lecture au groupe d'API `spdx.softwarecomposition.kubescape.io` (list/get sur `workloadconfigurationscans`) pour le cluster cible.

#### Mappages du connecteur

1. Saisissez l'URL du serveur API du cluster (ou un identifiant convivial du cluster) dans le champ **Location**.
2. Collez le **kubeconfig** du cluster cible dans le champ `kubeconfig`. Vous pouvez éventuellement définir `kube_context` pour sélectionner un contexte à l'intérieur de celui-ci, et `cluster_name` pour étiqueter les Produits découverts.
3. Chaque espace de noms disposant de résultats de posture est découvert comme un Enregistrement ; mappez ceux que vous souhaitez importer vers des Produits DefectDojo.

Les constatations sont dérivées par contrôle échoué : le nom du contrôle et la charge de travail identifient la Constatation, la sévérité provient du facteur de score du contrôle, l'identifiant du contrôle devient l'identifiant de vulnérabilité, et chaque Constatation renvoie vers sa référence de contrôle à l'adresse `https://hub.armosec.io/docs/`.
