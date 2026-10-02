---
title: Organisations
description: Comprendre les Organisations dans DefectDojo Pro
audience: pro
weight: 1
---

**ORGANISATIONS** → Actifs → Engagements → Tests → Constatations

## Aperçu

**Les Organisations** se situent tout en haut de la hiérarchie des produits de DefectDojo. Les Organisations se distinguent des objets descendants de la hiérarchie — Actifs, Engagements, Tests et Constatations — car elles ne constituent pas des cibles de scan techniques, mais servent avant tout d'abstractions organisationnelles permettant de compartimenter vos efforts de sécurité selon :
- Le domaine d'activité
- L'équipe de développement
- L'équipe de sécurité
- Les applications logicielles
- La famille de produits globale
- Le client ou la filiale
- La structure de reporting
- etc.

Le fil conducteur des exemples ci-dessus illustre l'utilité essentielle des Organisations : elles doivent généralement représenter des frontières stables et durables au sein de votre programme de sécurité.

## Données et structure des Organisations

Comme les Organisations ne sont pas scannées directement, le seul champ obligatoire pour les créer est un nom. Au-delà de cela, elles servent de conteneurs pour les Actifs et leurs Engagements, Tests et Constatations descendants.

Lors de la création d'une Organisation, réfléchissez à la manière dont sa structure influencera votre reporting. Avez-vous principalement besoin que les Organisations représentent les équipes travaillant sur les projets (Actifs) qu'elles contiendront ? Ou les Organisations représenteraient-elles mieux des projets globaux englobant différentes itérations des projets (Actifs) qu'ils contiennent ?

Si vous disposez d'une seule Organisation regroupant toutes les informations pertinentes pour un domaine d'activité ou une équipe de développement donné, la représenter comme une Organisation facilitera un reporting plus fluide, plutôt que de devoir compiler un rapport à partir de divers Actifs et Organisations.

Si un projet logiciel particulier comporte de nombreux déploiements ou versions distincts, il peut être pertinent de créer une seule Organisation couvrant l'ensemble du périmètre du projet, chaque version existant alors en tant qu'Actif individuel. Dans certains workflows, les Organisations peuvent également être utilisées pour séparer les étapes du cycle de vie logiciel : une Organisation pour « En développement », une Organisation pour « En production », etc.
​
Les Organisations peuvent être utilisées pour déterminer l'accès aux filiales, aux entreprises acquises ou à d'autres unités commerciales réglementées à des fins de RBAC. Dans les entreprises complexes, où de nombreux projets uniques ont des règles d'accès différentes, les Organisations sont particulièrement pertinentes.

En définitive, la décision quant à la manière d'utiliser les Organisations et les Actifs dépend de la façon dont vous souhaitez le mieux refléter votre structure organisationnelle unique et les besoins de votre équipe de sécurité.

Voici quelques exemples de structures pour vous aider à déterminer si vos objets doivent être désignés comme des Organisations ou des Actifs.

- **Organisation** : Division des paiements
    - Actif : API de paiements - Production
    - Actif : API de paiements - Staging
    - Actif : Worker de facturation

- **Organisation** : Produit logiciel A
    - Actif : Portail Web
    - Actif : Backend mobile

En outre, voici un guide illustratif permettant de déterminer si un élément est mieux représenté par une Organisation ou par un Actif :

| Organisations | Actifs |
|--------------|--------|
| Unités commerciales | Applications individuelles |
| Départements | Déploiements/environnements |
| Domaines de propriété de sécurité | Composants d'infrastructure |
| Familles de produits | Microservices spécifiques |
| Reporting au niveau du portefeuille | Cibles de scan |
| Clients | Versions logicielles spécifiques |

Comme indiqué, votre structure peut varier selon les besoins de sécurité qui vous sont propres.

## Accès aux Organisations

Les Organisations sont accessibles depuis la barre latérale. Le sous-menu donne accès à Toutes les Organisations, ainsi qu'à l'option permettant de créer une nouvelle Organisation.

![image](images/org_ss1.png)

## Vue de l'Organisation

La vue d'une Organisation contient divers tableaux et graphiques permettant d'interpréter son statut en un coup d'œil. Cela comprend :

- **Description**
- **Commerce**
    - Indique si l'Organisation a été déterminée comme Critique ou Clé
        - Cocher Critique ou Clé est utilisé uniquement à des fins de filtrage
- **Membres assignés** (Utilisateurs DefectDojo)
- **Groupes d'utilisateurs assignés**
    - Groupes d'utilisateurs assignés à l'Organisation pour le contrôle des permissions. Vous trouverez plus d'informations sur les groupes d'utilisateurs [ici](/admin/user_management/create_user_group/).
- **Liste des Actifs au sein de l'Organisation**

## Travailler avec les Organisations

### Créer des Organisations

Il existe deux façons de créer des Organisations :

- Depuis l'option **Nouvelle organisation** du menu latéral
- Depuis le bouton **Nouvelle organisation** en haut de la liste Toutes les Organisations

### Modifier des Organisations

Les Organisations peuvent être modifiées en cliquant sur **Modifier l'organisation** dans le menu d'engrenage en haut à droite de la vue de l'Organisation. Ce même menu est également accessible en cliquant sur le menu kebab ⋮ à gauche de l'Organisation dans la vue Toutes les Organisations.

Tous les champs qui peuvent ensuite être modifiés sont également disponibles lors de la création de l'Organisation.

### Supprimer des Organisations

La suppression d'une Organisation peut être effectuée en sélectionnant **Supprimer l'organisation** dans les paramètres de l'Organisation.

Comme les Organisations se situent au sommet de la hiérarchie, leur suppression entraîne la suppression de tout l'historique de sécurité en aval, des relations et des objets enfants, tels que :
- Tout Actif, Engagement et Test contenu dans l'Organisation
- Tout l'historique de sécurité associé, y compris les Constatations et les intégrations
- Tout Epic Jira lié
- Toutes les notes et tous les fichiers téléversés associés aux Actifs, Engagements et Tests au sein de cette Organisation

La suppression d'une Organisation est irréversible. Si vous souhaitez « démanteler » une organisation sans supprimer les données sous-jacentes (par exemple, pour conserver des enregistrements de tests logiciels historiques à des fins d'audit), vous pouvez modifier le nom de l'Organisation ou ajouter une Étiquette indiquant qu'elle est dans un état obsolète.

## Organisations et métadonnées

Les Organisations sont destinées à représenter des frontières de propriété structurelle ou de reporting, plutôt que des classifications légères. Des attributs tels que le statut de déploiement, les libellés internes ou les états de workflow temporaires peuvent être mieux représentés par des étiquettes ou des métadonnées plutôt que par des Organisations distinctes.

## Limites des Organisations

Les Organisations établissent à la fois des limites de reporting et d'accès au sein de DefectDojo. Étant donné que les intégrations, les permissions RBAC, la propriété, les métriques et les modèles de déduplication héritent fréquemment de la structure des Organisations, définir des limites claires dès le départ permet d'éviter par la suite une prolifération de la hiérarchie et une fragmentation du reporting.

### Constatations et automatisation

Bien que les intégrations soient généralement configurées sur des objets de niveau inférieur tels que les Actifs, les Engagements ou les Constatations, les Organisations définissent néanmoins les limites de propriété, de reporting et d'accès au sein desquelles ces intégrations fonctionnent.

Les permissions se propagent vers le bas, ce qui signifie que l'accès à une Organisation accorde automatiquement l'accès à tous les objets qu'elle contient (par exemple, les Actifs, Engagements, Tests et Constatations).

Le modèle RBAC de DefectDojo peut être utilisé pour contrôler l'accès des utilisateurs humains, mais aussi pour restreindre l'accès des tokens API à des Organisations particulières.

Pour plus d'informations sur les rôles utilisateur, consultez notre article [Introduction aux types de permissions](/admin/user_management/set_user_permissions/#introduction-to-permission-types).

### Propriété

En tant qu'objets de premier niveau, les Organisations impliquent également la propriété des objets enfants qu'elles contiennent. Le suivi des SLA, les workflows de remédiation, le routage des tickets et la gouvernance générale fonctionnent tous plus efficacement lorsque les Organisations ont été configurées pour refléter fidèlement les personnes qui en sont responsables.

### Métriques/Reporting

Les tableaux de bord de métriques, les tuiles et les vues peuvent être filtrés par Organisation, ce qui en fait un élément essentiel de la façon dont vos données de sécurité sont calculées, visualisées et finalement exportées.

À des fins de reporting, il est généralement plus simple de combiner plusieurs Organisations en un seul document que de subdiviser une seule Organisation en plusieurs documents. Nous recommandons donc de configurer les Organisations au niveau de granularité le plus pertinent pour les rapports de votre équipe. Par exemple, il n'est pas nécessaire de représenter une grande division commerciale comme une Organisation si vous allez principalement produire des rapports pour les différents départements de cette division.

Structurer efficacement vos Organisations pour refléter vos besoins de reporting est essentiel pour évaluer avec précision votre posture de sécurité. Pour plus d'informations sur les Métriques, cliquez [ici](/metrics_reports/pro_metrics/pro__overview/).

### Déduplication

La déduplication dans DefectDojo s'effectue au niveau de l'Actif et n'est pas affectée par l'Organisation parente.
