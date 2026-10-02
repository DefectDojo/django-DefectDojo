---
title: 🎨 Changements de l'interface Pro
description: Travailler avec différentes interfaces dans DefectDojo
draft: 'false'
weight: 5
audience: pro
aliases:
- /fr/en/about_defectdojo/ui_pro_vs_os
---

Fin 2023, DefectDojo, Inc. a publié une nouvelle interface pour DefectDojo Pro, qui est désormais l'interface par défaut de cette édition.

L'interface Pro apporte les améliorations suivantes à DefectDojo :

- Un design moderne et soigné utilisant Vue.js.
- Une livraison des données et des temps de chargement optimisés, en particulier pour les grands jeux de données.
- L'accès à de nouvelles fonctionnalités Pro, notamment les vues [Upstream Connectors](/connectors/upstream/about/), [Universal Importer](/import_data/pro/specialized_import/external_tools/) et [Pro Metrics](/metrics_reports/pro_metrics/pro__overview/).
- Des flux de travail d'interface améliorés : meilleur filtrage, meilleurs tableaux de bord et meilleure navigation.

## Passer à l'interface Pro

Pour accéder à l'interface Pro, ouvrez votre menu Options utilisateur dans le coin supérieur droit.  Vous pouvez également revenir à l'interface Classique depuis ce même menu.

![image](images/beta-classic-uis.png)

## Changements de navigation

![image](images/pro_ui_overview.png)

1. La **barre latérale** a été réorganisée en quatre catégories parentes : Dashboards, Import, Manage et Settings.

2. La page d'accueil, les [capacités de connexion API native alimentées par l'IA](/metrics_reports/ai/mcp_server_pro/), Pro Metrics et la vue Calendrier sont toutes accessibles sous Dashboards.

4. Les méthodes d'import se trouvent dans la section Import : configurez des [Connectors](/connectors/about/) pour récupérer les Constatations depuis vos scanners (Upstream) ou les transmettre à des outils de suivi des problèmes (Downstream), utilisez le formulaire [Add Findings](/import_data/import_scan_files/pro__import_scan_ui/) pour ajouter des Constatations, utilisez [Smart Upload](/import_data/pro/specialized_import/smart_upload/) pour gérer les outils de scan d'infrastructure, ou utilisez nos outils externes—[Universal Importer et DefectDojo CLI](/import_data/pro/specialized_import/external_tools/)—pour simplifier les processus d'import et de réimport des Constatations et des objets associés.

5. La section **Manage** vous permet de visualiser différents objets dans la [Hiérarchie des produits](/asset_modelling/os_hierarchy/product_hierarchy/), avec des vues pour les Types de produit, les Produits, les Engagements, les Tests, les Constatations, les Acceptations du risque, les Points de terminaison et les Composants.  Il existe des sections supplémentaires pour générer des rapports (Report Builder), utiliser des enquêtes (Surveys), ainsi qu'un [moteur de règles](/automation/rules_engine/about/).

5. La section **Settings** vous permet de configurer votre instance DefectDojo, notamment votre License, vos Cloud Settings, vos Users, votre Feature Configuration et vos Enterprise Settings de niveau administrateur. (Les intégrations ont été déplacées vers **Import > Connectors > Downstream Connectors**.)

6. La section **Settings** regroupe les pages d'administration, organisées en System, Users & Permissions, Finding Workflow, Configuration, Notifications, Operations et License & Support, avec une page **All Settings** qui liste et permet de rechercher parmi toutes ces pages. Voir [Le menu Settings](/navigation/pro__settings_menu/).

7. L'interface Pro dispose également d'un **nouveau format de tableau**, utilisé dans la [Hiérarchie des produits](/asset_modelling/os_hierarchy/product_hierarchy/) pour faciliter la navigation.  Il est possible de cliquer sur chaque colonne pour appliquer un filtre pertinent, et les colonnes peuvent être réorganisées pour présenter les données comme vous le souhaitez.

8. Le tableau dispose également d'un menu **« Toggle Columns »** qui permet d'ajouter ou de supprimer des colonnes du tableau.

## Filtrer le tableau

Dans cette capture d'écran, nous filtrons toutes les Constatations qui se trouvent dans « Sam's Awesome Product ». Une fois que nous cliquons sur Apply, le contenu de cette liste de Constatations se met à jour pour refléter le filtre choisi.

![image](images/pro_ui_sams_filter.png)

## Nouveaux tableaux de bord

De nouvelles visualisations de métriques sont incluses dans l'interface Pro. Tous ces rapports peuvent être filtrés et exportés en PDF pour les partager avec un public plus large.

![image](images/program_insights.png)

- Le tableau de bord **Executive Insights** affiche l'état actuel de vos Produits et Types de produit.
- **Priority Insights** affiche les Constatations les plus critiques, avec la possibilité de filtrer par différentes périodes, Types de produit, Produits et Étiquettes.
- Le tableau de bord **Program Insights** affiche l'efficacité de votre équipe de sécurité et les économies réalisées en séparant les doublons et les faux positifs des Constatations exploitables.
- **Remediation Insights** affiche l'efficacité de votre équipe dans la remédiation des Constatations.
- **Tool Insights** affiche l'efficacité de votre suite d'outils (et des pipelines Upstream Connector) pour détecter et signaler les vulnérabilités.
