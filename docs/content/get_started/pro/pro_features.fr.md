---
title: 📊 Liste des fonctionnalités Pro
description: Liste des fonctionnalités Pro dans DefectDojo
draft: 'false'
weight: 4
chapter: true
exclude_search: true
audience: pro
aliases:
- /fr/en/about_defectdojo/pro_features
---

Voici une liste des nombreuses fonctionnalités supplémentaires de DefectDojo Pro, accompagnée de liens vers la documentation pour les voir en action :

## UX améliorée

### Interface Pro

L'interface de DefectDojo a été repensée dans DefectDojo Pro pour être plus rapide, plus fonctionnelle, entièrement personnalisable, et pour mieux naviguer dans des volumes de données de niveau entreprise.  Elle inclut également un mode sombre.  
Consultez notre [Guide de l'interface Pro](/get_started/about/ui_pro_vs_os/) pour plus d'informations.

![image](images/enabling_deduplication_within_an_engagement_2.png)

### Recherche globale

Trouvez n'importe quelle Constatation, Actif, Engagement et bien plus depuis une seule barre de recherche dans la barre supérieure. La recherche globale de DefectDojo Pro parcourt vos objets grâce à une recherche plein texte Postgres rapide et tolérante aux fautes de frappe.

Consultez notre [Guide de la recherche globale](/navigation/pro__global_search/) pour plus d'informations.

### Actifs/Organisations

DefectDojo Pro permet une meilleure visualisation organisationnelle pour de grandes listes de dépôts ou d'autres structures métier.  Consultez la [documentation Actifs/Organisations](/asset_modelling/pro_hierarchy/asset_hierarchy/) pour plus de détails.

![image](images/asset_hierarchy_diagram.png)

### Priorité des constatations

DefectDojo Pro peut pré-trier vos Constatations par Priorité et Risque, ce qui permet à votre équipe d'identifier et de corriger en premier vos problèmes les plus critiques.
Consultez notre [Guide de la priorité des constatations](/asset_modelling/pro_hierarchy/priority_sla/) pour plus de détails.

### Moteur de règles

Le Moteur de règles de DefectDojo Pro vous permet de scripter des actions groupées automatisées et de créer des workflows personnalisés pour traiter les Constatations et d'autres objets, sans expérience de programmation requise.

Consultez notre [Guide du moteur de règles](/automation/rules_engine/about) pour plus d'informations.

![image](images/rules_engine_4.png)

### Sensei

**Sensei** (BÊTA) de DefectDojo Pro est une fonctionnalité de scan et correction propulsée par l'IA : connectez un dépôt via une GitHub App, et Sensei le scanne, importe les constatations, et ouvre des pull requests qui les corrigent — avec un workflow d'aperçu préalable, de sorte que rien ne s'exécute (et aucun coût de LLM n'est engagé) tant que vous n'avez pas approuvé.

Consultez notre [Guide Sensei](/sensei/about_sensei/) pour plus d'informations.

### Tableaux de bord et rapports Pro

Générez des [rapports et métriques instantanés](/get_started/about/ui_pro_vs_os/#new-dashboards) pour partager la posture de sécurité de vos applications et dépôts, évaluer vos outils de sécurité et analyser la performance de votre équipe dans le traitement des problèmes de sécurité.

Les graphiques de la page d'accueil peuvent être exportés au format SVG, et les données utilisées pour créer les graphiques peuvent également être exportées sous forme de tableau. 

De plus, DefectDojo Pro inclut plusieurs nouveaux [tableaux de bord d'analyse](/metrics_reports/pro_metrics/pro__overview/), offrant des métriques enrichies pour les différents publics de votre programme de sécurité.

### Réglage de la déduplication

Les paramètres avancés de Déduplication vous permettent d'affiner la manière dont DefectDojo identifie et gère les constatations en double. Ajustez la Déduplication au sein d'un même outil, **entre outils**, et lors du réimport pour une correspondance précise entre tous les outils de sécurité que vous avez choisis et les constatations de vulnérabilités. 

Consultez notre [Guide de réglage de la déduplication](/triage_findings/finding_deduplication/pro__deduplication_tuning/) pour plus d'informations.

![image](images/deduplication_tuning.png)

## Import simplifié

### Davantage d'options d'import

DefectDojo Pro inclut quatre méthodes d'import supplémentaires : [Universal Importer](/import_data/pro/specialized_import/external_tools/), [Upstream Connectors](/connectors/upstream/about/), [Universal Parser](/supported_tools/parsers/universal_parser/), et [Smart Upload](/import_data/pro/specialized_import/smart_upload/).

![image](images/pro_import_methods.png)


### Imports en arrière-plan

Pour les rapports de niveau entreprise, DefectDojo Pro propose une méthode d'upload optimisée qui traite les Constatations en arrière-plan.

### Outils CLI

Construisez rapidement un pipeline en ligne de commande pour importer, réimporter et exporter des données vers votre instance DefectDojo Pro à l'aide de nos applications Universal Importer et DefectDojo-CLI ; aucun script d'API n'est nécessaire (disponible pour Windows, Macintosh ou Linux).

Consultez notre [Guide des outils externes](/import_data/pro/specialized_import/external_tools/) pour plus d'informations.

### Upstream Connectors

DefectDojo peut se connecter instantanément à des outils de scan de niveau entreprise pour importer de nouvelles données de Constatations, créant un pipeline d'import automatisé qui fonctionne immédiatement, sans qu'il soit nécessaire de configurer des appels API ou des tâches cron. 

Consultez notre [Guide Upstream Connectors](/connectors/upstream/about/) pour plus d'informations.

![image](images/add_edit_connectors_2.png)

Les outils pris en charge par Upstream Connectors incluent :

* Anchore
* AWS Security Hub
* BurpSuite
* Checkmarx ONE
* Dependency-Track
* Probely
* Semgrep
* SonarQube
* Snyk
* Tenable
* Wiz

### Universal Parser (Bêta)

Si vous utilisez un outil de scan non pris en charge ou personnalisé, ou si vous souhaitez simplement que DefectDojo traite un rapport un peu différemment, utilisez Universal Parser de DefectDojo Pro pour transformer n'importe quel rapport .json ou .csv en un ensemble exploitable de Constatations. Votre parser analysera et mappera les données comme vous le souhaitez.

Consultez notre [Guide Universal Parser](/import_data/pro/specialized_import/universal_parser//) pour plus d'informations.

![image](images/universal_parser_3.png)

## Gestion des fonctionnalités optionnelles

Beaucoup des capacités ci-dessus sont optionnelles et sont livrées derrière un feature flag, afin que vous puissiez les adopter quand vous êtes prêt. Un superutilisateur peut activer ou désactiver la plupart d'entre elles directement depuis **Settings > Feature Flags**, sans avoir à contacter le support.

Consultez le guide [Feature Flags](/admin/feature_flags/pro__feature_flags/) pour savoir comment activer une fonctionnalité, et pourquoi une fonctionnalité peut être verrouillée ou indisponible selon votre type d'installation.

## Support

Les abonnements DefectDojo Pro incluent un support de classe mondiale pour les installations sur site (on-premise) comme pour les installations Cloud.  Notre équipe est disponible pour aider votre organisation à mettre en œuvre et à optimiser votre utilisation de DefectDojo Pro.  Votre abonnement inclut :

- **Support complet** : des tickets de support et des sièges illimités sont disponibles pour assister toute votre équipe.
- **Attention d'ingénierie dédiée** : les problèmes signalés par les utilisateurs, les bugs et les demandes de fonctionnalités reçoivent une attention prioritaire de la part de notre équipe d'ingénierie.
- **Gestion SaaS** : nous assurons la surveillance, la maintenance et les sauvegardes de toutes les instances SaaS.
