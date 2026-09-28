---
title: À propos de DefectDojo
date: 2021-02-02 20:46:29+01:00
draft: false
type: docs
weight: 1
aliases:
- /fr/en/about_defectdojo/about_docs
---

<div class="version-opensource">

![image](images/dashboard.png)

</div>
<div class="version-pro">

![image](images/Introduction_to_Dashboard_Features.png)

</div>


<span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo, Inc. et les contributeurs open source maintiennent cette documentation pour prendre en charge à la fois l'édition Community et l'édition Pro de DefectDojo.</span>

## Qu'est-ce que DefectDojo ?

DefectDojo est une plateforme de Developer Security Operations (DevSecOps). DefectDojo simplifie le DevSecOps en servant d'agrégateur automatique pour votre suite d'outils de sécurité, ce qui vous permet d'organiser facilement votre travail de sécurité et de communiquer la posture de sécurité de votre organisation aux autres parties prenantes.

Bien que l'automatisation des processus de sécurité et l'intégration aux pipelines de développement soient les objectifs ultimes de DefectDojo, ce logiciel est avant tout un outil de suivi des vulnérabilités de sécurité, conçu pour ingérer, organiser et standardiser les rapports de nombreux outils de sécurité.

### Que fait DefectDojo ?

DefectDojo dispose de fonctionnalités intelligentes pour améliorer et affiner les résultats de vos outils de sécurité, notamment la capacité de :

- Suivre et rendre compte des Constatations de sécurité en contexte
- Faire respecter les SLA en contexte
- Gérer les Faux positifs, les Risques acceptés et les autres décisions de tri
- Éliminer les doublons grâce à l'algorithme de déduplication de DefectDojo
- S'intégrer à des logiciels externes de suivi de projet
- Fournir des métriques/rapports sur l'ensemble des dépôts et des branches de développement grâce à l'intégration CI/CD
- Coordonner la gestion traditionnelle des tests d'intrusion (Pen tests)
- Définir et faire respecter des SLA pour les procédures de remédiation des vulnérabilités
- Créer et suivre les Risques acceptés pour les vulnérabilités de sécurité

En définitive, le modèle Produit:Engagement de DefectDojo vous permet de faire l'inventaire de votre environnement de développement et de replacer immédiatement les nouvelles Constatations de sécurité dans leur contexte.

---
Voici quelques exemples de façons dont DefectDojo peut être mis en œuvre, avec Matt Tesauro, cofondateur et CTO de DefectDojo :
<iframe width="560" height="315" src="https://www.youtube.com/embed/44vv-KspHBs?si=OwfGHs2VTQ886-FB" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

---

## DefectDojo Open Source

Les fonctionnalités principales de DefectDojo sont disponibles dans DefectDojo Open Source.

Cette édition de DefectDojo comprend :

- L'import/réimport pour l'ensemble des plus de 500 outils pris en charge
- L'API REST
- Les fonctionnalités de déduplication
- Une interface, des métriques et des fonctionnalités de rapport limitées
- La capacité d'intégration avec Jira

Pour les équipes gérant un volume de Constatations plus restreint, DefectDojo Open Source constitue un excellent point de départ.

### Guides d'installation

Il existe plusieurs méthodes prises en charge pour installer l'édition Open Source de DefectDojo ([disponible sur Github](https://github.com/DefectDojo/django-DefectDojo)) :

[Docker Compose](https://github.com/DefectDojo/django-DefectDojo/blob/master/readme-docs/DOCKER.md) est la méthode la plus simple pour installer le programme principal et les services requis pour exécuter DefectDojo.
Notre guide [Architecture](/get_started/open_source/architecture/) vous donne un aperçu de chaque service et composant utilisé par DefectDojo.
[Exécution en production](/get_started/open_source/running-in-production/) répertorie les exigences système, les optimisations de performance et les processus de maintenance pour exécuter DefectDojo sur un serveur de production (avec Docker Compose).

Kubernetes n'est pas entièrement pris en charge au niveau Open Source, mais ce guide peut être consulté et utilisé comme point de départ pour intégrer DefectDojo dans une architecture Kubernetes.

Si vous rencontrez des difficultés avec une installation Open Source, nous vous recommandons vivement de poser vos questions sur le [Slack OWASP](https://owasp.org/slack/invite). Les membres de notre communauté sont actifs sur le canal #defectdojo et peuvent vous aider à résoudre les problèmes que vous rencontrez.

## 🟧 Édition DefectDojo Pro

<iframe width="560" height="315" src="https://www.youtube.com/embed/XUES0mCCGOI?si=2GEnd1iHlLcQE0R3" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

DefectDojo, Inc. héberge une édition Pro de ce logiciel à des fins commerciales. En plus d'une interface moderne et soignée, DefectDojo Pro comprend :

* [Connectors](/connectors/upstream/about/) : des intégrations API prêtes à l'emploi avec des scanners de niveau entreprise (comme Checkmarx One, BurpSuite, Semgrep et bien d'autres)
* **Des méthodes d'import configurables** : [Universal Parser](/supported_tools/parsers/universal_parser/), [Smart Upload](/import_data/pro/specialized_import/smart_upload/)
* **[Des outils CLI](/import_data/pro/specialized_import/external_tools/)** pour une intégration rapide avec vos systèmes
* **[Des intégrations de suivi de projet supplémentaires](/connectors/issue_tracking/)** : ServiceNow, Azure DevOps, GitHub et GitLab
* **[Des métriques améliorées](/metrics_reports/pro_metrics/pro__overview/)** pour les rapports destinés aux dirigeants et les analyses de haut niveau
* **[Priorité et risque](/asset_modelling/pro_hierarchy/priority_sla/)** pour identifier les Constatations les plus urgentes, à l'échelle du système
* Un **support Premium** et un accompagnement pour la mise en œuvre au sein de votre organisation

L'édition Pro est proposée en tant qu'offre SaaS hébergée dans le cloud, et est également disponible pour une installation sur site.

Pour en savoir plus sur DefectDojo Pro, consultez notre [page Tarifs](https://defectdojo.com/pricing).

## Démos en ligne

Des démos en ligne sont disponibles pour les versions Open Source et Pro de DefectDojo. Les deux sont accessibles avec les identifiants suivants :

- Nom d'utilisateur : `admin`
- Mot de passe : `1Defectdojo@demo#appsec`

Ces démos sont préchargées avec des données d'exemple et sont réinitialisées quotidiennement.

### Démo Open Source

Un exemple fonctionnel de DefectDojo (édition Open Source) est disponible à l'adresse [https://demo.defectdojo.org/](https://demo.defectdojo.org/).

### Démo Pro

Un exemple fonctionnel de DefectDojo Pro est disponible à l'adresse
[https://pro.demo.defectdojo.com/](https://pro.demo.defectdojo.com/).

## Apprendre DefectDojo

Que vous soyez utilisateur Pro ou Open Source, nous mettons à votre disposition de nombreuses ressources pour vous aider à démarrer avec DefectDojo.

* Consultez nos [intégrations d'outils de sécurité](/supported_tools/) prises en charge pour vous aider à intégrer DefectDojo dans votre programme DevSecOps.
* Notre équipe maintient une [chaîne YouTube](https://www.youtube.com/@defectdojo) qui héberge des tutoriels, des enregistrements d'Office Hours et d'autres contenus.

## Nous contacter

Pour entrer en contact avec l'équipe de DefectDojo, Inc., vous pouvez toujours nous écrire à [hello@defectdojo.com](mailto:hello@defectdojo.com).

Nous sommes régulièrement présents sur [LinkedIn](https://www.linkedin.com/company/33245534) et organisons également des présentations en ligne pour les professionnels AppSec, accessibles en direct ou à la demande. Vous pouvez découvrir les événements à venir sur notre [page Événements](https://defectdojo.com/events) ou visionner les présentations passées sur notre [chaîne YouTube](https://www.youtube.com/@defectdojo).

### Autocollants

Vous cherchez de superbes autocollants DefectDojo pour votre ordinateur portable ? Pour vous remercier de faire partie de la communauté DefectDojo, vous pouvez vous inscrire pour recevoir gratuitement des autocollants DefectDojo. Pour plus d'informations, consultez [ce lien](https://defectdojo.com/defectdojo-sticker-request).
