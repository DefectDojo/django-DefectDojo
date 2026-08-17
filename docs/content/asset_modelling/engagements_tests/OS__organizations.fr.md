---
title: Organisations
description: Comprendre les Organisations dans DefectDojo OS
audience: opensource
weight: 1
aliases:
- /fr/asset_modelling/engagements_tests/os_producttype/
- /fr/en/asset_modelling/engagements_tests/os_producttype/
---

**ORGANISATIONS** → Actifs → Engagements → Tests → Constatations

## Aperçu 

**Les Organisations** se situent tout en haut de la hiérarchie des objets de DefectDojo. Les Organisations se distinguent des objets qui descendent dans la hiérarchie (Actifs, Engagements, Tests et Constatations) car elles ne constituent pas des cibles de scan techniques, mais servent avant tout d'abstractions organisationnelles qui compartimentent vos efforts de sécurité selon : 
- Domaine d'activité
- Équipe de développement
- Équipe de sécurité
- Applications logicielles
- Famille de produits globale
- Client ou filiale
- Structure de reporting
- etc. 

Le fil conducteur des exemples ci-dessus illustre l'utilité essentielle des Organisations : elles doivent généralement représenter des frontières stables et durables au sein de votre programme de sécurité.

## Données et structure des Organisations 

Comme les Organisations ne sont pas scannées directement, le seul champ obligatoire pour les créer est un nom. Au-delà de cela, elles servent de conteneurs pour les Actifs et les Engagements, Tests et Constatations qui en descendent. 

Lors de la création d'une Organisation, réfléchissez à la façon dont sa structure influencera votre reporting. Avez-vous principalement besoin que les Organisations représentent les équipes travaillant sur les projets (Actifs) qu'elles contiendront ? Ou les Organisations représenteraient-elles mieux des projets globaux contenant différentes itérations des projets (Actifs) en leur sein ?

Si vous disposez d'une seule Organisation contenant toutes les informations pertinentes pour un domaine d'activité ou une équipe de développement donné, le fait de la représenter comme une Organisation facilitera un reporting plus fluide, plutôt que de devoir assembler un rapport à partir de divers Actifs et Organisations. 

Si un projet logiciel particulier comporte de nombreux déploiements ou versions distincts, il peut être utile de créer une seule Organisation couvrant l'ensemble du périmètre du projet et de faire exister chaque version en tant qu'Actif individuel. Dans certains flux de travail, les Organisations peuvent également être utilisées pour séparer les étapes du cycle de vie logiciel : une Organisation pour « En développement », une Organisation pour « En production », etc.

Les Organisations peuvent servir à déterminer l'accès aux filiales, aux entreprises acquises ou à d'autres unités commerciales réglementées à des fins de RBAC. Dans les entreprises complexes, où il existe de nombreux projets uniques avec des règles d'accès différentes, les Organisations sont particulièrement pertinentes.

En définitive, la décision quant à la façon d'utiliser les Organisations et les Actifs dépend de la meilleure manière dont vous souhaitez refléter votre structure organisationnelle unique et les besoins de votre équipe de sécurité. 

Voici quelques exemples de structures pour vous aider à déterminer si vos objets doivent être désignés comme des Organisations ou des Actifs. 

- **Organisation** : Division des paiements
    - Actif : API de paiement - Production
    - Actif : API de paiement - Staging
    - Actif : Billing Worker

- **Organisation** : Produit logiciel A
    - Actif : Portail Web
    - Actif : Backend mobile

De plus, voici un guide illustratif permettant de déterminer si un élément est mieux représenté par une Organisation ou par un Actif : 

| Organisations | Actifs |
|--------------|--------|
| Unités commerciales | Applications individuelles |
| Départements | Déploiements/environnements |
| Domaines de responsabilité en matière de sécurité | Composants d'infrastructure |
| Familles de produits | Microservices spécifiques |
| Reporting au niveau du portefeuille | Cibles de scan |
| Clients | Versions logicielles spécifiques |

Comme indiqué, votre structure peut varier en fonction des besoins de sécurité qui vous sont propres.

## Accéder aux Organisations 

Les Organisations sont accessibles depuis la barre latérale. Le sous-menu propose également l'option de créer de nouvelles Organisations.

![image](images/organization_ss1.png)

### Vue Organisation 

La vue d'une Organisation contient divers tableaux et graphiques permettant d'interpréter son état d'un coup d'œil. Cela inclut : 
- **Description**
- **Case à cocher Clé/Critique**
    - Cocher Critique ou Clé sert uniquement à des fins de filtrage 
- **Liste des Actifs au sein de l'Organisation**
- **Utilisateurs autorisés** (Utilisateurs DefectDojo)

## Utiliser les Organisations 

### Créer des Organisations 

Il existe deux façons de créer des Organisations : 

- Depuis l'option **Ajouter une Organisation** dans le menu latéral
- Depuis le bouton **Ajouter une Organisation** en haut de la liste Toutes les Organisations 

### Modifier des Organisations 

Les Organisations peuvent être modifiées en cliquant sur **Modifier** dans le menu déroulant situé en haut à droite du tableau Description dans la vue de l'Organisation. Ce même menu est également accessible en cliquant sur le menu kebab ⋮ à gauche de l'Organisation dans la liste Toutes les Organisations.

Tous les champs modifiables qui en découlent sont également disponibles lors de la création de l'Organisation.

### Supprimer des Organisations 

La suppression d'une Organisation s'effectue en sélectionnant **Supprimer l'Organisation** dans les paramètres de l'Organisation. 

Étant donné que les Organisations se situent au sommet de la hiérarchie, leur suppression entraîne la suppression de tout l'historique de sécurité en aval, des relations et des objets enfants, tels que : 
- Tous les Actifs, Engagements et Tests contenus dans l'Organisation
- Tout l'historique de sécurité associé, y compris les Constatations et les intégrations
- Toutes les Epics Jira liées
- Toutes les notes et tous les fichiers téléversés associés aux Actifs, Engagements et Tests de cette Organisation

La suppression d'une Organisation est irréversible. Si vous souhaitez « désaffecter » une Organisation sans supprimer les données sous-jacentes (par exemple, pour conserver des enregistrements de tests logiciels historiques à des fins d'audit), vous pouvez modifier le nom de l'Organisation ou ajouter une Étiquette pour indiquer qu'elle est dans un état obsolète.

## Organisations et métadonnées

Les Organisations sont destinées à représenter des responsabilités structurelles ou des frontières de reporting, plutôt que des classifications légères. Des attributs tels que le statut de déploiement, les libellés internes ou les états temporaires de flux de travail peuvent être mieux représentés par des étiquettes ou des métadonnées plutôt que par des Organisations distinctes.

## Frontières des Organisations 

Les Organisations établissent à la fois des frontières de reporting et d'accès au sein de DefectDojo. Comme les intégrations, les permissions RBAC, la propriété, les métriques et les modèles de déduplication héritent fréquemment de la structure des Organisations, définir des frontières claires dès le départ permet d'éviter par la suite une prolifération de la hiérarchie et une fragmentation du reporting.

### Constatations et automatisation 

Bien que les intégrations soient généralement configurées sur des objets de niveau inférieur tels que les Actifs, les Engagements ou les Constatations, les Organisations définissent malgré tout les frontières de propriété, de reporting et d'accès dans lesquelles ces intégrations opèrent.

Les permissions se propagent vers le bas, ce qui signifie que l'accès à une Organisation accorde automatiquement l'accès à tous les objets qu'elle contient (par ex., Actifs, Engagements, Tests et Constatations). 

Le modèle RBAC de DefectDojo peut être utilisé pour contrôler l'accès des utilisateurs humains, mais peut également restreindre l'accès des jetons API à des Organisations particulières.

Pour plus d'informations sur les rôles utilisateur, consultez notre article [Permissions](/admin/user_management/os__authorized_users/).

### Propriété 

En tant qu'objets de premier niveau, les Organisations impliquent également la propriété des objets enfants qu'elles contiennent. Le suivi des SLA, les flux de remédiation, l'acheminement des tickets et la gouvernance générale fonctionnent tous de manière plus fluide lorsque les Organisations ont été configurées pour refléter fidèlement les personnes responsables de ces dernières.

### Métriques/Reporting 

Les tableaux de bord de métriques, les tuiles et les vues peuvent être filtrés par Organisation, ce qui en fait un composant essentiel de la façon dont vos données de sécurité sont calculées, visualisées et finalement exportées. 

À des fins de reporting, il est généralement plus simple de combiner plusieurs Organisations en un seul document que de subdiviser une seule Organisation en documents distincts. Nous recommandons donc de configurer les Organisations au niveau de granularité le plus adapté aux rapports de votre équipe. Par exemple, il n'est pas nécessaire de représenter une grande division commerciale comme une Organisation si vous comptez principalement produire des rapports pour les différents départements de cette division.

Structurer efficacement vos Organisations pour refléter vos besoins de reporting est essentiel pour évaluer avec précision votre posture de sécurité. Pour plus d'informations sur les Métriques, cliquez [ici](/metrics_reports/dashboards/introduction_dashboard/).

### Déduplication 

La déduplication dans DefectDojo s'effectue au niveau de l'Actif et n'est pas affectée par l'Organisation parente.
