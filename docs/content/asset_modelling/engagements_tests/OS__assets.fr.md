---
title: Actifs
description: Comprendre les Actifs dans DefectDojo OS
audience: opensource
weight: 2
aliases:
- /fr/asset_modelling/engagements_tests/os__products/
- /fr/en/asset_modelling/engagements_tests/os__products/
---

Organisations → **ACTIFS** → Engagements → Tests → Constatations

## Vue d'ensemble

Les **Actifs** sont au centre de l'organisation du travail de sécurité au sein de la hiérarchie d'objets de DefectDojo. Les Actifs représentent tout projet, programme, logiciel ou bien physique que votre équipe de sécurité teste, et hébergent tout le travail de sécurité et l'historique de tests liés à l'objectif de test. Voici des exemples d'Actifs :
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

En général, un Actif doit représenter la « chose » dont vous souhaitez suivre la posture de sécurité dans le temps. Cela inclut l'historique de tests associé, les Constatations, les métriques, la propriété, les intégrations, et les flux de remédiation liés à cette « chose ».

### Exemples d'Actifs

Les Actifs peuvent devenir encore plus granulaires selon les besoins de votre organisation. Par exemple, vous pouvez envisager de créer des Actifs DefectDojo distincts dans les scénarios suivants :

- « ExampleAsset » a une version Windows, une version Mac et une version Cloud
- « ExampleAsset 1.0 » utilise des composants logiciels complètement différents de « ExampleAsset 2.0 », et les deux versions sont activement prises en charge par votre entreprise.
- L'équipe chargée de travailler sur « ExampleAsset version A » est différente de l'équipe d'Actif chargée de travailler sur « ExampleAsset version B », et doit se voir attribuer des permissions de sécurité différentes en conséquence.

Bien que vous puissiez également choisir de représenter ces variations sous forme d'Engagements au sein d'un seul Actif, le RBAC ne peut être défini qu'au niveau des Actifs ou des Organisations, ce qui peut limiter l'accès des utilisateurs à l'Engagement approprié (ainsi qu'aux Tests et Constatations au sein de ces Engagements) s'ils sont organisés ainsi. Pour plus d'informations sur le RBAC et les permissions dans DefectDojo, cliquez [ici](/admin/user_management/about_perms_and_roles/).

## Données d'Actif

Les Actifs incluent toujours les éléments suivants :

- **Nom unique**
- **Description**
- **Organisation**
- **Configuration SLA**

Les métadonnées optionnelles d'Actif incluent :

- **Étiquettes**
- **Informations sur le personnel** (par ex. responsable de l'Actif, responsable d'équipe, contact technique, etc.)
- **Réglementations** (par ex. HIPAA, GLBA, OPPA, etc.)
- **Criticité métier**
- **Plateforme** (par ex. API, Desktop, IoT, Mobile, Web, etc.)
- **Cycle de vie** (par ex. Construction, Production, Retrait, etc.)
- **Origine** (par ex. bibliothèque tierce, achetée, open source, etc.)
- **Enregistrements utilisateur** (c'est-à-dire le nombre estimé d'enregistrements utilisateur dans l'Actif)
- **Revenu**

Ces métadonnées améliorent le filtrage, le reporting et la priorisation au sein de votre programme de sécurité, mais surtout, les Actifs contiennent également tous les Engagements, Tests et Constatations liés aux efforts de test entourant cet Actif. Toutes les Constatations issues des Tests remontent finalement au niveau de l'Actif, ce qui permet un suivi à long terme, une analyse des tendances et un reporting.

## Accéder aux Actifs

Les Actifs sont accessibles depuis la barre latérale. Le sous-menu offre également la possibilité de créer un nouvel Actif.

![image](images/asset_ss3.png)

### Permissions

Des règles de contrôle d'accès basé sur les rôles (RBAC) peuvent être appliquées aux Actifs, ce qui limite la capacité des membres de l'équipe à les consulter et à interagir avec eux.

Les permissions se propagent vers le bas, ce qui signifie que l'accès à un Actif accorde automatiquement l'accès à tous les objets au sein de cet Actif (par ex. Engagements, Tests et Constatations).

Pour plus d'informations sur les rôles utilisateur, consultez notre [article d'introduction aux rôles](/admin/user_management/about_perms_and_roles/).

## Vue d'Actif

Les vues d'Actif contiennent divers tableaux et graphiques permettant d'interpréter le statut d'un Actif en un coup d'œil. Cela inclut :

- **Métadonnées**
    - Incluant l'Organisation, la criticité métier, le revenu, et d'autres détails ajoutés depuis les paramètres de l'Actif.
- **Métriques**
    - Une liste des Constatations ouvertes au sein de l'Actif, regroupées par sévérité
- **Accord de niveau de service par sévérité**
    - Applique la configuration SLA de l'Actif définie dans les paramètres aux Constatations au sein de l'Actif.
- **Technologies**
    - Par ex. next.js, vue.js, npm v.1.2.3, Django, nginx, Hugo
- **Réglementations**
- **Progression du Benchmark**
- **Membres**
- **Groupes**
- **Contacts**
- **Notifications**
    - Active ou désactive les notifications en fonction d'événements spécifiques (par ex. un Engagement a été ajouté ou clôturé)

## Utilisation des Actifs

### Créer des Actifs

Il existe plusieurs façons de créer un nouvel Actif, notamment :

- Le bouton **Ajouter un Actif** dans la liste Tous les Actifs

![image](images/asset_ss2.png)

- Depuis le menu déroulant du tableau des Actifs dans la vue d'une Organisation
    - Cela créera automatiquement l'Actif au sein de cette Organisation.

![image](images/asset_ss1.png)

- Le bouton **Ajouter un Actif** dans la barre latérale

![image](images/asset_ss5.png)

### Modifier des Actifs

Un Actif peut être modifié depuis ses paramètres, accessibles de deux façons :

- Le bouton **Modifier** dans le menu kebab ⋮ à gauche de l'Actif dans la vue Tous les Actifs

![image](images/asset_ss6.png)

- Le bouton **Modifier** dans le menu déroulant **Paramètres** de la vue de l'Actif

![image](images/asset_ss7.png)

### Supprimer des Actifs

L'option permettant de supprimer un Actif se trouve en bas des mêmes menus décrits dans la section **Modifier des Actifs** ci-dessus. Cette action est irréversible. Un Actif ne peut pas être clôturé puis rouvert ultérieurement.

La suppression d'un Actif supprime également ce qui suit :
- Tout Engagement et Test contenu dans l'Actif
- Tout l'historique de sécurité associé, y compris les Constatations et les intégrations
- Toute Épopée Jira liée
- Toutes les notes et tous les fichiers importés associés aux Engagements et Tests de l'Actif

## Limites des Actifs

### Déduplication

Les Actifs sont « cloisonnés » et n'interagissent pas avec d'autres Actifs. Les fonctionnalités intelligentes de DefectDojo, telles que la Déduplication, ne s'appliquent que dans le contexte d'un seul Actif. Les Constatations réparties sur différents Actifs ne seront pas dédupliquées automatiquement.

### Métriques

La plupart des rapports et métriques agrègent les données au niveau de l'Actif, ce qui fait des Actifs l'unité principale de mesure et de suivi du risque.

Par conséquent, de nombreuses métriques clés sont calculées par Actif, notamment :

- Nombre total de Constatations (par sévérité ou statut)
- Délai moyen de remédiation (MTTR)
- Taux de conformité et de dépassement des SLA
- Évolution des tendances de risque dans le temps

Cela signifie que la manière dont les Actifs sont structurés a un impact direct sur l'exactitude et l'utilité des rapports. Par exemple, regrouper plusieurs systèmes sans rapport sous un seul Actif peut masquer la visibilité du risque, tandis que des structures d'Actif trop granulaires peuvent fragmenter le reporting, rendant difficile l'identification de tendances plus larges.

Les métriques spécifiques à un Actif sont accessibles depuis le bouton **Métriques** dans la barre supérieure de la vue de l'Actif choisi.

![image](images/asset_ss8.png)

### Pipeline CI/CD

Les pipelines CI/CD automatisent l'import des résultats d'analyse. Quelle que soit la méthode d'intégration, tous les imports d'analyse doivent être associés à un Actif, ce qui fait de l'Actif le point d'ancrage des données de sécurité pilotées par le pipeline.

Lorsqu'un pipeline soumet des résultats d'analyse, il doit soit :

- Spécifier un Actif existant (et éventuellement un Engagement), soit
- Être configuré de manière à toujours faire correspondre les résultats au bon Actif

Toutes les Constatations importées hériteront du contexte de l'Actif, y compris la propriété, les permissions, la configuration SLA et le périmètre de reporting.

En pratique, les Actifs doivent être définis de manière à refléter la façon dont les systèmes sont construits et déployés au sein du CI/CD, afin de garantir que les résultats de sécurité soient systématiquement associés à la bonne application ou au bon service.

### Relations Jira

Les Actifs peuvent être mappés directement à des Projets Jira, qui poussent les Constatations de l'Actif vers une instance Jira.

Étant donné que les Constatations héritent du risque, de la priorité et de la propriété de leur Actif parent, l'Actif détermine en pratique le contexte de remédiation qui alimente les tickets Jira et les flux de travail des connecteurs en aval.

Il est important de noter que les Actifs constituent également le principal facteur déterminant des caractéristiques SLA d'une Constatation. Ainsi, le SLA d'une Constatation dépend de la configuration SLA de son Actif parent. Plus d'informations sur les configurations SLA sont disponibles [ici](/asset_modelling/os_hierarchy/os__sla_configuration/#main-content).
