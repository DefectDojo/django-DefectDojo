---
title: Glossaire
weight: 1
---

Voici un glossaire simple destiné à faciliter la compréhension des différentes fonctionnalités de DefectDojo, avec une indication précisant si chaque fonctionnalité définie est présente/applicable dans la version Pro de DefectDojo, dans la version OS, ou dans les deux.

## Hiérarchie des Produits (Les deux)
Le modèle structurel utilisé pour organiser les données de sécurité au sein de DefectDojo, composé des Organisations → Actifs → Engagements → Tests → Constatations.
## Organisation (Les deux)
Un objet hiérarchique de premier niveau qui sert d'objet parent aux Actifs dans DefectDojo Pro. Il fournit un contexte partagé pour la gouvernance, le contrôle d'accès et le reporting sur l'ensemble des Actifs enfants.
## Actif (Les deux)
Un objet de premier plan représentant une entité système déployable ou logique (par exemple, une application, un hôte, un environnement) au sein des Organisations. Les Actifs prennent en charge les relations parent-enfant et des métadonnées métier plus riches dans la version Pro, mais ne prennent pas en charge les relations parent-enfant dans la version OS.
### Hiérarchie des Actifs (Pro)
Un modèle de relation parent-enfant entre les Actifs qui permet l'héritage du contexte et l'agrégation des Constatations.
## Engagement (Les deux)
Une activité de sécurité délimitée représentant une fenêtre de test, un pipeline ou un contexte d'évaluation.
## Test (Les deux)
Une exécution unique d'un scanner ou d'une évaluation manuelle au sein d'un Engagement. Les Tests stockent les métadonnées d'exécution et constituent le point d'ingestion des Constatations.
## Service (Les deux)
Un sous-objet facultatif utilisé pour attribuer des Constatations à un composant ou une interface spécifique au sein d'un Actif. Les Services sont surtout utiles dans OS DefectDojo, leur fonctionnalité étant reprise et enrichie par la Hiérarchie des Actifs dans la version Pro.
## Composants (Les deux)
Une bibliothèque tierce, un module logiciel ou une dépendance externe suivie dans DefectDojo Pro. Les Composants importés sont dérivés des données de scan et associés aux Constatations. Dans l'interface Pro, le tableau des Composants agrège, pour chaque Composant, les décomptes de Constatations Active, Doublon et le nombre total de Constatations, et reste renseigné même lorsque toutes les Constatations associées sont Atténué.
## Constatation (Les deux)
L'objet de vulnérabilité le plus granulaire de la Hiérarchie des Produits de DefectDojo, représentant un problème de sécurité distinct.
### Statut de la Constatation (Les deux)
L'état actuel du cycle de vie d'une Constatation (par exemple, Active, Vérifié, Inactive/Atténué, En cours d'examen, Risque accepté, Faux positif, Hors périmètre). Le Statut de la Constatation détermine son inclusion dans les métriques et les tableaux de bord.
### Priorité/Risque de la Constatation (Pro)
Une valeur calculée ou dérivée représentant l'urgence de remédiation, combinant la sévérité à des facteurs contextuels tels que la criticité de l'actif ou l'exploitabilité. La priorité est distincte de la sévérité brute et sert à la prise de décision fondée sur le risque.
### Groupes de Constatations (Les deux)
Un mécanisme permettant de regrouper des Constatations connexes au sein des Organisations, des Actifs ou des outils. Les Groupes de Constatations permettent une analyse consolidée et un reporting de plus haut niveau.
## Point de terminaison (Les deux)
Un emplacement accessible sur le réseau (URL, IP, port) associé à une Constatation. Les Points de terminaison fournissent le contexte technique d'exploitation.
## Import (Les deux)
Le processus d'ingestion des résultats de scan ou des constatations manuelles dans DefectDojo, généralement par le téléversement d'un fichier ou la soumission de données via l'API. Lors de l'import, DefectDojo analyse, normalise, déduplique et associe les constatations à l'Actif, à l'Engagement, au Test et aux objets associés appropriés.
## Réimport (Les deux)
L'action d'ingérer de nouveaux résultats de scan dans un Test existant. Le réimport met à jour l'état des Constatations en fonction de leur présence ou de leur absence dans les nouvelles données.
## Déduplication (Les deux)
Le processus consistant à corréler les Constatations entrantes avec celles déjà existantes à l'aide de hachages et d'une logique de correspondance, permettant un suivi historique à travers les exécutions de scan.
## Faux positif (Les deux)
Un état de Constatation indiquant que le problème est invalide ou non exploitable. Les faux positifs sont conservés à des fins d'audit mais exclus des calculs de risque.
## Acceptation du risque (Les deux)
Un état de workflow indiquant une Constatation reconnue mais non résolue. Les risques acceptés restent visibles mais sont exclus de l'application des SLA.
## Métadonnées (Les deux)
Des données clé associées aux Tests ou aux Constatations, telles que le nom de la branche ou l'ID de build, généralement fournies via des pipelines CI/CD.
## Intégration CI/CD (Les deux)
Ingestion automatisée des résultats de scan pendant les workflows de build ou de déploiement. Les intégrations reposent généralement sur l'API et le framework d'import.
## API (Les deux)
Une interface RESTful utilisée pour gérer les objets DefectDojo de manière programmatique. L'API est le principal mécanisme d'automatisation et d'intégration aux pipelines.
## Webhook (Pro)
Un rappel HTTP sortant déclenché par des événements spécifiques (par exemple, la création d'une Constatation). Les Webhooks permettent une intégration en temps réel avec des systèmes externes.
## Configuration SLA (Pro)
Des définitions de politiques attribuant des délais de remédiation en fonction de la sévérité ou d'attributs de risque. Les SLA permettent l'application des délais et la mesure de la performance.
## Rôle utilisateur (Les deux)
Un ensemble de permissions définissant les actions autorisées au sein de DefectDojo. Les rôles appliquent le contrôle d'accès sur les Actifs et les Engagements.
## Universal Importer (Pro)
Un mécanisme d'ingestion flexible permettant d'importer des données de scan sans utiliser d'importeur spécifique à un outil. Il repose sur une correspondance de champs normalisée plutôt que sur des schémas de scanner prédéfinis.
## DefectDojo-CLI (Pro)
Une interface en ligne de commande utilisée pour interagir avec DefectDojo de manière programmatique. Le CLI est couramment utilisé dans les pipelines CI/CD pour automatiser le téléversement des scans et la gestion des objets.
## Connectors (Pro)
La zone unifiée de l'interface Pro (sous Import) regroupant tous les outils avec lesquels DefectDojo communique. Les Upstream Connectors récupèrent les constatations depuis les scanners ; les Downstream Connectors envoient les constatations vers les outils de suivi des tickets.
## Upstream Connectors / API Connectors (Pro)
Des connecteurs préconstruits et gérés qui récupèrent les constatations et l'inventaire des actifs dans DefectDojo depuis des scanners externes et des outils de sécurité via leurs API, réduisant ainsi le besoin de scripts personnalisés. Anciennement appelés API Connectors.
## Downstream Connectors (Pro)
Des intégrations gérées qui envoient les Constatations et les Groupes de Constatations depuis DefectDojo vers des systèmes de suivi des tickets (par exemple, Jira, Azure DevOps, GitHub). Anciennement appelés Integrations.
## Universal Parser (Pro)
Un moteur d'analyse généraliste utilisé par l'Universal Importer pour interpréter les données de scan entrantes. Il applique une logique cohérente de normalisation et de déduplication aux formats non pris en charge.
## Smart Upload (Pro)
Un workflow d'ingestion intelligent qui détermine automatiquement comment les résultats de scan doivent être associés aux Actifs ou aux Engagements, réduisant la configuration manuelle lors de l'import. Lorsqu'un hôte analysé appartient à plusieurs Actifs, une copie de la Constatation est créée dans chaque Actif correspondant.
## Executive Insights (Pro)
Des analyses de haut niveau, orientées métier, conçues pour un public dirigeant, mettant l'accent sur les tendances, l'exposition et la santé du programme plutôt que sur les Constatations individuelles.
## Priority Insights (Pro)
Des vues analytiques mettant en évidence les risques les plus critiques en fonction d'un score de priorité plutôt que de la seule sévérité, afin de faciliter une planification de la remédiation fondée sur le risque.
## Program Insights (Pro)
Des métriques et visualisations qui évaluent l'efficacité et la maturité d'un programme de sécurité dans le temps. Program Insights met l'accent sur les tendances, la couverture et la performance opérationnelle.
## Tool Insights (Pro)
Des analyses centrées sur la performance des scanners, leur couverture et leur contribution aux Constatations, aidant les équipes à optimiser l'utilisation des outils et à réduire le bruit.
## Rules Engine (Pro)
Un système d'automatisation piloté par des politiques qui applique une logique conditionnelle aux Constatations lors de l'ingestion ou d'événements du cycle de vie, automatisant les changements de sévérité, les affectations ou les workflows.
## Intégrations (Les deux)
Des connexions entre DefectDojo et des outils ou plateformes externes pour l'ingestion de données, les notifications ou l'automatisation des workflows. Pro propose des intégrations plus poussées et gérées, au-delà des importeurs basiques et de l'usage de l'API.
