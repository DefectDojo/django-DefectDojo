---
title: ☑️ Liste de contrôle du nouvel utilisateur
description: Bien démarrer avec DefectDojo
draft: 'false'
weight: 3
audience: opensource
---

Voici un aide-mémoire rapide que vous pouvez utiliser pour garantir une mise en œuvre réussie, d'une page blanche jusqu'à une application pleinement fonctionnelle.  Cet article suppose que vous avez **DefectDojo Community Edition** installé et fonctionnant dans votre environnement.

L'essence de DefectDojo est d'importer des données de sécurité, de les organiser, et de les présenter aux personnes qui ont besoin de les connaître.  Voici comment procéder dans DefectDojo Open Source :

### DefectDojo Open Source

1. Les utilisateurs Open Source peuvent commencer par créer leur premier [Product Type et Product](/asset_modelling/os_hierarchy/product_hierarchy/).  Une fois ceux-ci créés, ils peuvent [importer un fichier](/import_data/import_scan_files/os__import_scan_ui/) vers l'un de ces Produits via l'UI.

2. Maintenant que vous avez des données dans DefectDojo, envisagez d'étoffer la structure de vos Produits en consultant l'[aperçu de la hiérarchie des Produits](/asset_modelling/os_hierarchy/product_hierarchy/). La hiérarchie des Produits crée un inventaire fonctionnel de vos applications, ce qui vous aide à répartir vos données en catégories logiques. Ces catégories peuvent être utilisées pour appliquer des règles de contrôle d'accès, ou pour segmenter vos rapports selon l'équipe concernée.

3. Utilisez le [Report Builder](/metrics_reports/reports/using-the-report-builder/#opening-the-report-builder) pour résumer les données que vous avez importées. Les rapports peuvent être utilisés pour partager rapidement les Constatations avec des parties prenantes telles que les Product Owners.

Voilà l'essence de DefectDojo : importer des données de sécurité, les organiser, et les présenter aux personnes qui ont besoin de les connaître.

Toutes ces fonctionnalités peuvent être automatisées, et comme DefectDojo peut gérer plus de 500 outils (au moment de la rédaction), vous devriez avoir tout ce qu'il faut pour créer un inventaire de sécurité fonctionnel de l'ensemble de la production de votre organisation.

### Fonctionnalités Open Source
- Votre organisation utilise-t-elle Jira ? Découvrez comment utiliser notre [intégration Jira](/connectors/os_jira/os__jira_guide/) pour créer des tickets Jira à partir des données que vous ingérez.
- Prévoyez-vous de partager DefectDojo avec de nombreux utilisateurs de votre organisation ? Consultez nos guides sur la [gestion des utilisateurs](/admin/user_management/about_perms_and_roles/) et mettez en place un contrôle d'accès basé sur les rôles (RBAC).
- Prêt à vous lancer dans l'automatisation ? Découvrez comment utiliser l'[API DefectDojo](/import_data/import_scan_files/api_pipeline_modelling/) pour importer automatiquement de nouvelles données, et construire un pipeline CI/CD robuste.
