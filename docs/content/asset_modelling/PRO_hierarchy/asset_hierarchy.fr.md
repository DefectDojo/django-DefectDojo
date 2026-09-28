---
title: Hiérarchie des actifs
description: DefectDojo Pro - Refonte de la hiérarchie des produits
audience: pro
weight: 1
aliases:
- /fr/en/working_with_findings/organizing_engagements_tests/pro_assets_organizations
- /fr/asset_modelling/pro_hierarchy/assets_organizations
---

DefectDojo Pro étend les classes d'objets Produit/Type de produit afin d'offrir une plus grande flexibilité dans le modèle de données.

## Enabling the Hierarchy Feature

Les deux éléments ci-dessous sont distincts et sont contrôlés par des moyens différents.

### Asset Hierarchy

**La Hiérarchie des actifs** permet d'établir des relations parent/enfant entre les Actifs. La hiérarchie se consulte et se gère depuis l'onglet **Produit** de la navigation.

La Hiérarchie des actifs est disponible en version stable et activée sur toutes les instances, Cloud et On-Premise. Il n'y a rien à activer, et elle n'apparaît plus sur la page Feature Flags.

### Label Changes (optional)

**Les changements d'étiquettes** renomment « Product Type » en « Organization » et « Product » en « Asset » dans toute l'UI. Il s'agit d'une étape distincte de l'activation de la hiérarchie, qui peut être effectuée en même temps ou plus tard.

Les changements d'étiquettes sont activés par défaut depuis la version 3.0. Il existe deux contrôles, couvrant différentes parties de l'application :

* **UI Pro** (l'UI par défaut) : un superutilisateur active « Organization / Asset Relabeling » dans **Paramètres > Feature Flags**, sur les instances Cloud comme On-Premise. Les nouvelles étiquettes apparaissent au chargement de page suivant. Voir [Feature Flags](/admin/feature_flags/pro__feature_flags/).
* **Pages de l'UI classique et rapports générés** : leurs étiquettes et URL proviennent du paramètre de déploiement `DD_ENABLE_V3_ORGANIZATION_ASSET_RELABEL`, lu au démarrage de DefectDojo. En on-premise, définissez-le puis redémarrez DefectDojo. Sur [DefectDojo Pro (Cloud)](/get_started/pro/cloud/), envoyez un e-mail à [support@defectdojo.com](mailto:support@defectdojo.com) avec l'URL de votre instance.

Les deux sont activés par défaut, et la valeur de Feature Flags a été initialisée à partir du paramètre de déploiement : les deux concordent donc tant que vous n'en modifiez pas un seul. Gardez-les synchronisés si vous utilisez à la fois l'UI classique et l'UI Pro.

Notez que les changements d'étiquettes sont purement cosmétiques : les endpoints API et les noms de champs restent inchangés, de sorte que vos automatisations existantes continueront de fonctionner.

## Significant Changes

* Les **Types de produit** ont été renommés en « Organizations », et les **Produits** ont été renommés en « Assets ».  Depuis la version 3.0, ce changement de nom est activé par défaut. Voir [Label Changes](#label-changes-optional) pour les contrôles permettant de le désactiver.
* Les **Actifs** peuvent désormais avoir des relations parent/enfant entre eux, afin de sous-catégoriser plus finement les composants organisationnels.

### Organizations

Comme pour les Types de produit, les **Organisations** doivent être comprises comme une catégorie de premier niveau.  Vous pouvez les utiliser pour séparer les applications logicielles cœur de votre entreprise, ses départements ou ses fonctions métier.

Par exemple, vous pourriez créer une Organisation pour plusieurs regroupements de dépôts : « Core Application », « Infrastructure », « DevOps », « Analytics », « SDK » pourraient chacun contenir plusieurs dépôts de code.

Gardez à l'esprit que, pour les besoins de reporting, il est plus simple de combiner plusieurs Organisations en un seul document que de subdiviser une Organisation unique en plusieurs documents. Nous recommandons donc de configurer vos Organisations au niveau de granularité le plus adapté aux rapports de votre équipe. Par exemple, il n'est pas nécessaire de représenter une grande division de l'entreprise comme une seule Organisation si vous allez principalement produire des rapports sur les départements individuels de cette division.

### Assets

Les Actifs sont destinés à représenter des subdivisions de vos Organisations.  Cependant, contrairement aux Produits, les Actifs peuvent être imbriqués et avoir des relations parent-enfant entre eux.

## Asset Nesting Examples

### Asset-Level Branch Representation

Les branches de développement et de fonctionnalités peuvent être représentées de diverses façons ; des Engagements ou des Tests distincts sont des moyens existants pour représenter la différence entre vos branches de Production, de Dev, et vos autres branches de fonctionnalités.

Vous pouvez également les représenter à l'aide d'Actifs imbriqués.  Prenons l'arborescence d'Actifs suivante :

```
Core Application [Organization]
└── webapp-frontend
    ├── webapp-frontend/prod
    └── webapp-frontend/dev
        ├── webapp-frontend/dev/feature-a
        └── webapp-frontend/dev/feature-b
```

Dans cet environnement, chaque branche (`prod`, `dev`, `feature a`, `feature b`) pourrait avoir ses propres Engagements et Tests isolés des autres Actifs, afin qu'ils ne se dédupliquent pas entre eux.  Cette configuration peut également faciliter la navigation, les noms d'Actifs pouvant correspondre directement au chemin sur Git.

### Mono-Repo: Separate Components

Si vous utilisez un dépôt unique pour tout votre code, mais que différentes équipes contribuent à des répertoires au sein de ce dépôt, vous pouvez configurer votre imbrication d'Actifs pour représenter cette structure.

```
Core Application [Organization]
├── webapp-frontend [Parent Asset]
│   ├── mobile-ios
│   ├── mobile-android
│   └── mobile-sdk
├── webapp-backend [Parent Asset]
│   ├── database
│   └── api
└── infra [Parent Asset]
    ├── docker
    ├── kubernetes
    └── nginx
```

Dans ce diagramme, chaque élément sous « Core Application » pourrait être enregistré comme un Actif distinct, avec sa propre criticité métier (voir : [Priority & Risk](/asset_modelling/pro_hierarchy/priority_sla/#prioritization-engines)), son propre RBAC, ainsi que ses propres Engagements et Tests.  Vous pourriez continuer à tester, et stocker les résultats, sur l'Actif parent (par exemple, `webapp-backend`), mais vous pourriez aussi exécuter des tests isolés sur un Actif enfant particulier (par exemple, `database`).

### Pen Tests: Isolated RBAC

Si vous souhaitez stocker les résultats de tests d'intrusion au sein d'un même actif, mais que vous ne voulez pas que les testeurs puissent consulter les données de l'actif, vous pouvez créer des actifs enfants pour que chaque groupe de test y envoie ses résultats.

```
Core Application [Organization]
└── webapp-frontend [Parent Asset]
    ├── Pen Test Group A
    └── Pen Test Group B
```

Point essentiel : donner à un utilisateur un accès RBAC à un seul Actif enfant (par exemple `Pen Test Group A`) ne lui permet pas de voir les Constatations des autres Actifs enfants (par exemple `Pen Test Group B`), ni de voir les Constatations dans l'Actif parent (`webapp-frontend`).

L'Actif parent pourrait contenir des Engagements représentant des résultats CI/CD, des Tests internes, des données historiques, ou d'autres données de Constatations que vous ne voulez pas que des tiers puissent découvrir.  Créer un Actif enfant pour des résultats de Test spécifiques permet à votre équipe interne de produire des rapports sur ces résultats en combinaison avec l'état de l'Actif parent.

## Visualizing Assets - Hierarchy

Vous pouvez visualiser la structure des Actifs dans DefectDojo, et modifier les relations à l'aide de l'option Hiérarchie des actifs dans le menu.

![image](images/asset_hierarchy.png)

L'ouverture de la Hiérarchie des actifs affiche un tableau de tous vos Actifs, qui peut être filtré.  Sélectionner un ou plusieurs Actifs dans ce tableau génère un diagramme de hiérarchie.

![image](images/asset_hierarchy_diagram.png)

### Diagram navigation

Les icônes en haut à gauche du diagramme de hiérarchie permettent de zoomer et dézoomer.  Cliquer-glisser dans ce diagramme permet de le faire défiler.

Chaque Actif est représenté par un seul nœud dans ce diagramme, qui peut être déplacé à des fins d'affichage.

Les Actifs sont reliés entre eux par des chemins étiquetés, qui représentent le type de relation qu'ils entretiennent les uns avec les autres.  Actuellement, `parent` est la seule étiquette prise en charge.

### Exploring Asset nodes

Chaque nœud d'Actif peut être manipulé en cliquant sur les boutons bleus.  Ces boutons n'apparaissent que lorsqu'un nœud d'Actif est sélectionné (en cliquant sur le nœud).

![image](images/asset_hierarchy_node.png)

* 👁️ (icône œil) vous amène directement à la Vue Actif correspondante (anciennement appelée Vue Produit).
* ✏️ (icône crayon) ouvre une fenêtre modale avec le formulaire Modifier l'actif (anciennement appelé formulaire Modifier le produit)
* ➕ (icône plus) vous permet d'ajouter un nouvel Actif enfant à cet Actif.  L'Actif n'a pas besoin d'être actuellement visible dans le diagramme, mais doit appartenir à la même Organisation.
* ✥ (icône quatre flèches) permet de changer l'Actif parent de l'Actif actuellement sélectionné.
* 🗑️ (icône corbeille) permet de supprimer la relation parent d'un Actif. Cette icône n'apparaît que si un Actif a déjà un Parent.

Si votre diagramme affiche un Actif dont les Actifs parents ne sont pas sélectionnés, vous pouvez cliquer sur le bouton Load More pour compléter le diagramme avec l'Actif parent (ainsi que les enfants de cet Actif parent).

![image](images/assets_loadmore.png)

## Notes

* Notez que les périmètres de déduplication n'ont pas changé ; les Actifs ne dédupliquent les Constatations qu'en leur sein, et ne prennent pas en compte les Constatations d'autres Actifs, quelles que soient les relations Parent/Enfant.
* Les périmètres RBAC n'ont pas changé dans ce système ; chaque Actif reste considéré comme un objet individuel pour l'attribution des permissions.  Aucun nouvel héritage RBAC n'a été créé.
  * Donner à un utilisateur l'accès à une Organisation entière lui donne toujours accès à tous les Actifs contenus dans cette Organisation (comme pour les Types de produit).
  * Donner à un utilisateur l'accès à un seul Actif ne lui donne pas accès aux Actifs parents ou enfants associés, ni à l'Organisation.
* Il n'y a pas de limite au nombre de relations Parent/Enfant qui peuvent être créées. En théorie, vous pourriez représenter l'intégralité de la structure de répertoires d'un dépôt à l'aide d'Actifs distincts si vous le souhaitiez.
* Les relations cycliques ne sont pas autorisées : un Actif parent ne peut pas être l'enfant de l'un de ses Actifs enfants.
