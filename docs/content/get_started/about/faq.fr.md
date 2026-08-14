---
title: ❓ Foire aux questions
description: FAQ DefectDojo
draft: 'false'
weight: 2
chapter: true
aliases:
- /fr/en/about_defectdojo/faq
---

Voici quelques questions fréquemment posées sur l'utilisation de DefectDojo, aussi bien dans DefectDojo Pro que dans DefectDojo OS.

## Questions générales

### Comment organiser mes tests de sécurité dans DefectDojo ?

Bien que DefectDojo puisse prendre en charge n'importe quel environnement de sécurité ou de test, l'équipe de sécurité et les opérations de chacun sont différentes, il n'existe donc pas d'approche universelle pour l'utiliser. Nous avons un article très détaillé sur les [cas d'usage courants](/get_started/common_use_cases/common_use_cases/) qui présente des exemples de la façon dont différentes organisations appliquent le RBAC et le modèle de données de DefectDojo pour répondre à leurs besoins.

### Quels sont les flux de travail recommandés pour les tests de sécurité dans DefectDojo ?

DefectDojo est conçu pour être la source de vérité centrale de la posture de sécurité de votre organisation, et il peut répondre à différents besoins selon les exigences de votre organisation, comme :

- Permettre aux utilisateurs d'identifier les constatations en double entre les scans et les outils, réduisant ainsi la lassitude face aux alertes.
- Faire respecter les SLA sur les vulnérabilités, garantissant que votre organisation traite chaque Constatation dans un délai approprié.
- [Envoyer des tickets](/connectors/issue_tracking/) vers Jira, ServiceNow ou d'autres logiciels de suivi de projet, permettant à votre équipe de développement d'intégrer la remédiation des problèmes dans son processus de publication standard sans avoir à apprendre un autre outil de gestion de projet.
- S'intégrer à des [pipelines CI/CD](/import_data/import_scan_files/api_pipeline_modelling/) automatisés pour ingérer automatiquement les données de rapport depuis les dépôts, jusqu'au niveau de la branche.
- Créer des [rapports](/metrics_reports/reports/) sur n'importe quel ensemble de vulnérabilités ou de contexte logiciel, pour partager rapidement les résultats de scan ou les mises à jour de statut avec les parties prenantes.
- Établir des flux de travail d'acceptation et d'atténuation, prenant en charge le suivi formel de la gestion des risques.


DefectDojo est conçu pour prendre en charge et standardiser votre flux de travail de sécurité actuel. Toutes ces méthodes peuvent être utilisées pour améliorer les processus de votre équipe et s'adapter à votre façon de fonctionner actuelle.

### Quelles fonctionnalités sont disponibles dans DefectDojo Pro ?

DefectDojo Pro étend davantage les flux de travail ci-dessus, en ajoutant :

- Une [interface améliorée](/get_started/about/ui_pro_vs_os/) conçue pour la rapidité et l'efficacité lors de la navigation dans des volumes de données de niveau entreprise. Elle inclut également un mode sombre.
- La capacité de [pré-trier vos Constatations](/asset_modelling/pro_hierarchy/priority_sla/) par Priorité et Risque, permettant à votre équipe d'identifier et de corriger en premier les problèmes les plus critiques.
- Un [moteur de règles](/automation/rules_engine/about) pour scripter des actions groupées automatisées et créer des flux de travail personnalisés pour gérer les Constatations et d'autres objets, sans expérience en programmation requise.
- Des [capacités de génération de rapports et de métriques améliorées](/get_started/about/ui_pro_vs_os/#new-dashboards) pour partager facilement la posture de sécurité de vos applications et dépôts.
- Des [paramètres de déduplication avancés](/triage_findings/finding_deduplication/pro__deduplication_tuning/) pour affiner la façon dont DefectDojo identifie et gère les constatations en double.
- Des capacités d'import optimisées, telles que :
  - Une méthode d'upload optimisée qui traite les Constatations en arrière-plan.
  - La capacité de créer rapidement un [pipeline en ligne de commande](/import_data/pro/specialized_import/external_tools/) à l'aide de nos applications Universal Importer et DefectDojo CLI, vous permettant d'importer, de réimporter et d'exporter facilement des données vers votre instance DefectDojo Pro.
  - Un [Universal Parser](/import_data/pro/specialized_import/universal_parser/) pour transformer n'importe quel rapport .json ou .csv en un ensemble exploitable de Constatations, DefectDojo Pro se chargeant d'analyser les données comme vous le souhaitez.
  - Des [Connectors](/connectors/upstream/about/), qui fournissent une connexion instantanée aux outils pris en charge pour importer de nouvelles données de Constatations, afin de mettre en place un pipeline d'import automatisé sans avoir besoin de configurer d'appels API ou de tâches cron.

### Comment DefectDojo gère-t-il le contrôle d'accès ?

DefectDojo peut être utilisé par de grandes équipes, et il est fortement recommandé de mettre en place le [RBAC (Rule Based Access Control)](/admin/user_management/about_perms_and_roles/), à la fois pour bien établir le contexte de chaque membre de l'équipe et pour contrôler l'accès à certaines parties de l'infrastructure.

L'attribution des rôles et des permissions se fait généralement au niveau Type de produit / Produit.  Chaque membre de l'équipe peut être affecté à un ou plusieurs Produits ou Types de produit, et peut se voir attribuer un rôle qui régit la façon dont il peut interagir avec les données de vulnérabilité qui s'y trouvent (lecture seule, lecture-écriture ou contrôle total).  Pour plus d'informations, consultez notre [guide RBAC](/admin/user_management/about_perms_and_roles/).

### Comment DefectDojo gère-t-il le contrôle d'accès pour une équipe d'utilisateurs ?

Que vous soyez une équipe de sécurité d'une seule personne pour une petite organisation ou un RSSI supervisant une multitude de projets logiciels, vous pouvez facilement organiser le [contrôle d'accès basé sur les rôles (RBAC)](/admin/user_management/about_perms_and_roles/) afin de bien établir le contexte de chaque membre de l'équipe et de contrôler l'accès à certaines parties de l'infrastructure.

En général, l'attribution des rôles et des permissions se fait au niveau du [Type de produit/Produit](/asset_modelling/os_hierarchy/product_hierarchy/). Chaque membre de l'équipe peut se voir attribuer un rôle relatif à un ou plusieurs Produits ou Types de produit, qui régit la façon dont il peut interagir avec les données de vulnérabilité qui s'y trouvent (par ex., lecture seule, lecture-écriture ou contrôle total).

## Flux de travail d'import

### Quels outils sont pris en charge par DefectDojo ?

DefectDojo prend en charge les rapports de [plus de 500](/supported_tools/) outils de sécurité commerciaux et open source.

Si vous cherchez à ajouter un nouvel outil à votre suite, nous avons une liste d'outils Open Source recommandés que vous pouvez consulter [ici](https://defectdojo.com/blog/announcing-the-defectdojo-open-source-security-awards).

### Quelle est la différence entre Import et Reimport ?

Il existe deux méthodes différentes pour importer un seul rapport depuis un outil de sécurité :

- **Import** traite le rapport comme un enregistrement ponctuel unique. L'import d'un rapport crée un Test contenant les Constatations qui en résultent.
- **[Reimport](/import_data/import_intro/reimport/)** est utilisé pour mettre à jour un Test existant avec un nouvel ensemble de résultats. Si vous adoptez une approche plus ouverte de votre processus de test, vous pouvez réimporter en continu la dernière version de votre rapport dans un Test existant. DefectDojo comparera les résultats du rapport entrant à vos données existantes, enregistrera les changements, puis ajustera les Constatations du Test pour correspondre au dernier rapport.

Pour comprendre la différence, il est utile de considérer l'Import comme l'enregistrement d'une seule instance d'un événement de scan, et le Reimport comme la mise à jour d'un enregistrement continu de scan.

Voici une analogie : si vous étiez comptable, vous utiliseriez l'Import pour suivre un reçu unique, tandis que vous utiliseriez le Reimport pour tenir un registre continu des dépenses.

Les deux méthodes utilisent également la Déduplication différemment : alors que deux Tests Importés distincts dans le même Produit identifieront et étiquetteront les Constatations en double séparément, le Reimport ne créera aucune Constatation qu'il identifie comme [doublon](/en/working_with_findings/finding_deduplication/avoiding_duplicates_via_reimport/) au sein du Test.

De manière générale, si vous avez besoin d'un rapport ponctuel, l'Import est la meilleure méthode à utiliser. Si vous exécutez et ingérez en continu des rapports depuis un outil, le Reimport est la meilleure méthode pour garder les choses organisées.

### Comment puis-je résoudre les erreurs d'import ?

DefectDojo prend en charge une grande variété d'outils. Si vous constatez un comportement incohérent lors de l'import d'un rapport, nous vous recommandons de vérifier que la structure du fichier correspond à ce que l'outil attend. Consultez notre [liste des parsers](/supported_tools/) pour confirmer que votre outil est pris en charge, et vérifiez que le format du fichier correspond à ce que l'outil attend. Vous pouvez également comparer la structure à nos Tests Unitaires.

DefectDojo Pro dispose d'une méthode d'import Universal Parser qui vous permet de traiter n'importe quel fichier JSON, CSV ou XML. Les utilisateurs de DefectDojo OS peuvent écrire des parsers personnalisés dans le même but.

Enfin, les formats de rapport tiers sont connus pour changer sans préavis : notre communauté OS apprécie grandement les [PR et contributions](/get_started/contributing/how-to-write-a-parser/) qui permettent de maintenir nos parsers à jour.

### Comment dois-je gérer les gros fichiers de scan ?

L'import d'un rapport volumineux dans DefectDojo peut être un processus long. Les rapports de 2 Mo contiennent des quantités importantes de données, ce qui peut prendre beaucoup de temps à traduire en Constatations selon le format de rapport de l'outil de sécurité.

Notre approche recommandée est de décomposer les rapports volumineux avant l'import, afin de refléter les différentes sous-sections des données disponibles. Si votre outil de sécurité peut filtrer les résultats par projet logiciel, application ou autre contexte, exporter des rapports plus petits facilite le traitement et la catégorisation des données par DefectDojo. Cela présente également l'avantage supplémentaire d'organiser de manière proactive vos Constatations en fonction de la façon dont les données ont été découpées, ce qui rend la génération de rapports plus pertinente et plus rapide.

DefectDojo Pro peut traiter les rapports en arrière-plan. Cependant, les fichiers doivent quand même être téléversés et validés par DefectDojo avant que le processus de création des Constatations en arrière-plan ne puisse commencer.

### Comment connecter un pipeline CI/CD à DefectDojo ?

De nombreuses fonctionnalités principales de DefectDojo peuvent être entièrement automatisées.  Le CI/CD (ou tout autre type d'import automatisé) peut être géré en appelant l'[API REST DefectDojo](/import_data/import_scan_files/api_pipeline_modelling/).

Les utilisateurs de **DefectDojo Pro** ont également accès aux [outils en ligne de commande](/import_data/pro/specialized_import/external_tools/) **Universal Importer / DefectDojo CLI**, qui peuvent être installés pour s'exécuter dans de nombreux environnements automatisés.

## Gestion des Constatations

### Que signifie le statut d'une Constatation ?

Les Constatations peuvent avoir plusieurs statuts. Un statut Actif ou Inactif est toujours défini sur une Constatation, tandis que d'autres statuts tels que Vérifié, Faux positif ou Hors périmètre peuvent être appliqués selon votre appréciation.

Ces statuts sont décrits plus en détail dans notre guide [Définitions des statuts de Constatation](/triage_findings/findings_workflows/finding_status_definitions/), ainsi que des informations sur la façon dont ils peuvent être utilisés.

### Comment puis-je supprimer des Constatations de DefectDojo ?

De manière générale, nous recommandons de conserver les Constatations clôturées en tant qu'« Inactives » plutôt que de les supprimer purement et simplement, car il est important de conserver un historique dans le travail AppSec. Supprimer une Constatation supprimera définitivement toutes les notes et le suivi des métriques associés à cette Constatation, ce qui peut entraîner des rapports inexacts ou une archive incomplète.

Les Constatations peuvent être supprimées de DefectDojo de plusieurs façons :
- En exécutant une action de [suppression groupée](/triage_findings/findings_workflows/editing_findings/#bulk-delete-findings) sur les Constatations que vous souhaitez supprimer
- En appelant `DELETE /findings/{id}` via l'API
- En supprimant un objet parent, tel qu'un Test, un Engagement, un Type de produit ou un Produit.
  - Notez que les sous-classes ne sont pas conservées indépendamment de leur objet parent : la suppression d'un objet parent tel qu'un Type de produit supprimera tous les Produits, Engagements, Tests, Constatations et Points de terminaison présents dans ce Type de produit. À l'inverse, la suppression d'un Engagement préservera les Produits et les Types de produit qui le précèdent.

## Rapports et Jira

### Comment puis-je générer un rapport dans DefectDojo ?

Vous pouvez créer rapidement un rapport personnalisé dans DefectDojo à l'aide du [Générateur de rapports](/metrics_reports/reports/).

Les utilisateurs de DefectDojo Pro ont également accès à des [tableaux de bord de métriques destinés aux dirigeants](/get_started/about/ui_pro_vs_os/#new-dashboards) qui peuvent rendre compte des Types de produit, des Produits ou d'autres données en temps réel.

### Comment puis-je intégrer un outil de gestion de projet à DefectDojo ?

Dans les éditions Pro et Open Source de DefectDojo, les Constatations peuvent être poussées vers Jira sous forme d'Issues, ce qui vous permet d'intégrer la remédiation des problèmes avec votre équipe de développement.

DefectDojo Pro ajoute la prise en charge des [intégrations de suivi de projet supplémentaires](/connectors/issue_tracking/)** : ServiceNow, Azure DevOps, GitHub et GitLab.
