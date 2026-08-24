---
title: Actifs
description: Comprendre les Actifs dans DefectDojo Pro
audience: pro
weight: 2
---

Organisations → **ACTIFS** → Engagements → Tests → Constatations

## Aperçu

**Les Actifs** se situent au centre de l'organisation du travail de sécurité au sein de la hiérarchie des objets de DefectDojo. Les Actifs représentent tout projet, programme, logiciel ou actif physique testé par votre équipe de sécurité, et hébergent l'ensemble du travail de sécurité et de l'historique de tests relatifs à l'objectif de test. Voici des exemples d'Actifs :
- Versions logicielles
- Logiciels tiers 
- Machines virtuelles ou actifs en production
- Une application unique
- Un microservice
- Une API
- Une plateforme SaaS
- Une application mobile
- Un système interne
- Un service métier
- Une plateforme destinée aux clients
- Un environnement cloud ou un domaine d'infrastructure

En général, un Actif doit représenter la « chose » dont vous souhaitez suivre la posture de sécurité dans le temps. Cela inclut l'historique de tests associé, les Constatations, les métriques, la propriété, les intégrations et les flux de remédiation liés à cette « chose ».

### Exemples d'Actifs

Les Actifs peuvent devenir encore plus granulaires selon les besoins de votre organisation. Par exemple, vous pouvez envisager de créer des Actifs DefectDojo distincts dans les scénarios suivants :

- « ExampleAsset » possède une version Windows, une version Mac et une version Cloud
- « ExampleAsset 1.0 » utilise des composants logiciels complètement différents de « ExampleAsset 2.0 », et les deux versions sont activement maintenues par votre entreprise.
- L'équipe chargée de travailler sur « ExampleAsset version A » est différente de l'équipe chargée de l'Actif « ExampleAsset version B », et doit par conséquent se voir attribuer des permissions de sécurité différentes.

Bien que vous puissiez également choisir de représenter ces variations sous forme d'Engagements au sein d'un seul Actif, le RBAC ne peut être défini qu'au niveau des Actifs ou des Organisations, ce qui peut limiter l'accès des utilisateurs à l'Engagement approprié (ainsi qu'aux Tests et Constatations au sein de ces Engagements) s'ils sont organisés de cette façon. Pour plus d'informations sur le RBAC et les permissions dans DefectDojo, cliquez [ici](/admin/user_management/about_perms_and_roles/).

## Données de l'Actif

Les Actifs incluent toujours les composants suivants :

- **Organisation**
- **Nom unique**
- **Description**
- **Configuration SLA**
- **Moteur de priorisation**

Les métadonnées optionnelles de l'Actif incluent : 

- **Étiquettes**
- **Criticité métier**
- **Enregistrements utilisateur** (c'est-à-dire le nombre estimé d'enregistrements utilisateur dans l'Actif)
- **Chiffre d'affaires**
- **Informations sur le personnel** (par ex., Responsable de l'Actif, Responsable d'équipe, Contact technique, etc.)
- **Réglementations** (par ex., HIPAA, GLBA, OPPA, etc.)
- **Plateforme** (par ex., API, Desktop, IoT, Mobile, Web, etc.)
- **Cycle de vie** (par ex., Construction, Production, Retrait, etc.)
- **Origine** (par ex., Bibliothèque tierce, Achetée, Open Source, etc.)

Ces métadonnées améliorent le filtrage, le reporting et la priorisation au sein de votre programme de sécurité, mais surtout, les Actifs contiennent également tous les Engagements, Tests et Constatations liés aux efforts de test entourant cet Actif. Toutes les Constatations issues des Tests remontent finalement au niveau de l'Actif, permettant un suivi à long terme, une analyse des tendances et un reporting.

## Accéder aux Actifs 

Les Actifs sont accessibles depuis la barre latérale. Le sous-menu donne accès à la [Hiérarchie des Actifs](/asset_modelling/engagements_tests/pro__assets/#asset-nesting) et à Tous les Actifs, ainsi qu'à l'option de créer un nouvel Actif.

![image](images/assets_ss1.png)

### Permissions 

Des règles de contrôle d'accès basé sur les rôles (RBAC) peuvent être appliquées aux Actifs, ce qui limite la capacité des membres de l'équipe à les consulter et à interagir avec eux. 

Les permissions se propagent vers le bas, ce qui signifie que l'accès à un Actif accorde automatiquement l'accès à tous les objets qu'il contient (par ex., Engagements, Tests et Constatations). 

Pour plus d'informations sur les rôles utilisateur, consultez notre article [Introduction aux rôles](/admin/user_management/set_user_permissions/#introduction-to-permission-types).

## Vue Actif 

Les vues Actif contiennent divers tableaux et graphiques permettant d'interpréter l'état d'un Actif d'un coup d'œil. Cela inclut : 

- **Sévérité des Constatations ouvertes**
    - Une liste des Constatations ouvertes au sein de l'Actif, regroupées par sévérité
- **Aperçu de l'Actif**
    - Une répartition des différentes caractéristiques de l'Actif, notamment Description, Composants, Contacts, [Groupes d'utilisateurs](/admin/user_management/create_user_group/
), Membres, Technologies et Réglementations.
        - Technologies : next.js, vue.js, npm v.1.2.3, Django, nginx, Hugo
- **Métadonnées**
    - Y compris les Actifs parents et enfants, l'Organisation, la criticité métier, le chiffre d'affaires et d'autres détails ajoutés depuis les paramètres de l'Actif. 
- **Accord de niveau de service par sévérité**
    - Applique la configuration SLA de l'Actif définie dans les paramètres aux Constatations au sein de l'Actif. 
- **Répartition des Constatations par sévérité**
    - Un graphique des Constatations au sein de l'Actif, organisé par sévérité. 
- **Distribution des Constatations**
    - Une répartition des Constatations au sein de l'Actif, organisée par statut (par ex., Actif, Atténué, Statique et Dynamique)
- **Tous les Engagements**
    - Une liste des Engagements contenus dans l'Actif. 

## Utiliser les Actifs 

### Créer des Actifs 

Il existe deux façons de créer des Actifs : 

- Depuis l'option **Nouvel Actif** dans le menu latéral
- Depuis le bouton **Nouvel Actif** en haut de la liste Tous les Actifs 

## Modifier des Actifs 

Les Actifs peuvent être modifiés en cliquant sur **Modifier l'Actif** dans le menu représenté par une roue dentée, en haut à droite de la vue de l'Actif. Ce même menu est également accessible en cliquant sur le menu kebab ⋮ à gauche de l'Actif dans la vue Tous les Actifs. 

Tous les champs modifiables qui en découlent sont également disponibles lors de la création de l'Actif.

![image](images/assets_ss2.png)

### Supprimer des Actifs

La suppression d'un Actif s'effectue en sélectionnant **Supprimer l'Actif** dans les paramètres de l'Actif. Cette action est irréversible. Les Actifs ne peuvent pas être fermés puis rouverts ultérieurement. 

La suppression d'un Actif entraînera également la suppression des éléments suivants : 
- Tous les Engagements et Tests contenus dans l'Actif
- Tout l'historique de sécurité associé, y compris les Constatations et les intégrations
- Toutes les Epics Jira liées
- Toutes les notes et tous les fichiers téléversés associés aux Engagements et Tests de l'Actif

## Frontières de l'Actif 

### Déduplication 

Les Actifs sont « cloisonnés » et n'interagissent pas avec d'autres Actifs. Les fonctionnalités intelligentes de DefectDojo, telles que la Déduplication, ne s'appliquent que dans le contexte d'un seul Actif. Les Constatations réparties sur différents Actifs ne seront pas automatiquement dédupliquées.

### Reporting et métriques 

La plupart des rapports et métriques agrègent les données au niveau de l'Actif, faisant des Actifs l'unité principale de mesure et de suivi du risque.

Par conséquent, de nombreuses métriques clés sont calculées par Actif, notamment :

- Nombre total de Constatations (par sévérité ou statut)
- Délai moyen de remédiation (MTTR)
- Taux de conformité et de dépassement des SLA
- Évolution du risque dans le temps

Cela signifie que la façon dont les Actifs sont structurés aura un impact direct sur la précision et l'utilité des rapports. Par exemple, regrouper plusieurs systèmes sans lien sous un seul Actif peut masquer la visibilité du risque, tandis que des structures d'Actifs trop granulaires peuvent fragmenter le reporting, rendant difficile l'identification de tendances plus larges.

### Connecteurs 

Dans DefectDojo Pro, les Connecteurs sont associés à différents Actifs, ce qui en fait le principal point d'intégration entre DefectDojo et votre écosystème de sécurité plus large.

Une fois qu'un Connecteur a été rattaché à un Actif, il importera les résultats de scan et créera ou mettra à jour des Engagements, Tests et Constatations au sein de cet Actif.

Pour plus d'informations sur les Connecteurs, cliquez [ici](/connectors/upstream/about/#main-content). 

### Pipelines CI/CD 

Les pipelines CI/CD automatisent l'import des résultats de scan. Quelle que soit la méthode d'intégration, tous les imports de scan doivent être associés à un Actif, faisant de l'Actif le point d'ancrage des données de sécurité pilotées par pipeline.

Lorsqu'un pipeline soumet des résultats de scan, il doit soit :

- Spécifier un Actif existant (et éventuellement un Engagement), soit
- Être configuré de manière à toujours associer les résultats à l'Actif correct

Toutes les Constatations importées hériteront du contexte de l'Actif, y compris la propriété, les permissions, la configuration de priorité/risque et le périmètre de reporting.

En pratique, les Actifs doivent être définis de manière à refléter la façon dont les systèmes sont construits et déployés dans le cadre du CI/CD, afin de garantir que les résultats de sécurité soient systématiquement associés à l'application ou au service correct.

### SLA, priorité et risque

Dans DefectDojo Pro, les Constatations héritent de leurs objectifs SLA, de leur Priorité et de leur Risque de l'Actif qui les contient. Les métadonnées de l'Actif (par ex., criticité métier, chiffre d'affaires, etc.) sont utilisées pour calculer automatiquement les valeurs de Priorité et de Risque. 

Cela signifie qu'une même vulnérabilité peut recevoir un score de Priorité ou de Risque différent selon qu'elle affecte un système de développement interne ou un actif de production prenant en charge des opérations métier critiques.

### Relations Jira / Connecteur en aval

Les Actifs peuvent être associés directement à des instances [Jira](/connectors/downstream/pro__jira_guide/#main-content) ou d'[Intégrateurs](/connectors/toolreference/downstream/#main-content) (par ex. GitHub, GitLab, ServiceNow, etc.), qui poussent les Constatations de l'Actif vers l'extérieur, dans des systèmes externes de gestion de tickets/travail.

Étant donné que les Constatations héritent du risque, de la priorité et de la propriété de leur Actif parent, l'Actif détermine effectivement le contexte de remédiation qui alimente les tickets Jira et les flux de travail des Connecteurs en aval.

Il est important de noter que les Actifs constituent également le principal facteur déterminant des caractéristiques SLA d'une Constatation. Ainsi, le SLA d'une Constatation dépend de la configuration SLA de son Actif parent. Plus d'informations sur les configurations SLA sont disponibles [ici](/asset_modelling/pro_hierarchy/priority_sla/#working-with-slas).

## Imbrication des Actifs

DefectDojo prend en charge une relation parent-enfant entre deux Actifs au sein d'une même Organisation. Cela peut être configuré lors de la création de l'Actif ou dans les paramètres de l'Actif. 

Vous pouvez visualiser la structure des Actifs dans DefectDojo et modifier les relations à l'aide de l'option **Hiérarchie des Actifs** dans la barre latérale.

Après avoir sélectionné les Actifs à visualiser dans le tableau correspondant, cliquez sur **Voir la hiérarchie des Actifs** pour générer un organigramme des relations entre les Actifs choisis, le cas échéant.

Plus d'informations sur l'effet de l'imbrication des Actifs sur la déduplication, le RBAC et d'autres détails, ainsi que des exemples de cas d'usage, sont disponibles [ici](/asset_modelling/pro_hierarchy/asset_hierarchy/#asset-nesting-examples).
