---
title: Tableaux de bord personnalisables
description: Créez des tableaux de bord personnalisés dans DefectDojo Pro à partir
  de widgets disposés sur une grille glisser-déposer
draft: false
audience: pro
weight: 10
slug: custom-dashboards
aliases:
- /fr/en/customize_dojo/dashboards/about_custom_dashboard_tiles
- /fr/metrics_reports/dashboards/about_custom_dashboard_tiles
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Remarque : les tableaux de bord personnalisables (dispositions, widgets et catalogue de widgets) sont une fonctionnalité de DefectDojo Pro. Ils sont désactivés par défaut — un superutilisateur peut les activer depuis **Paramètres > Feature Flags**, aussi bien sur les instances Cloud que On-Premise.</span>

Les tableaux de bord personnalisables de DefectDojo Pro permettent à chaque utilisateur d'assembler sa propre page d'accueil à partir de **widgets** — compteurs, graphiques, classements, flux et notes — disposés sur une grille glisser-déposer. Au lieu d'un tableau de bord unique et fixe pour tout le monde, vous construisez les **dispositions** (layouts) qui comptent pour vous : une vue d'ensemble pour la direction, une file de triage, un tableau de vitesse de remédiation, une vue d'efficacité des scanners. Vous pouvez garder vos dispositions privées, les publier pour toute votre équipe, en définir une comme page d'accueil par défaut, et cloner n'importe quelle disposition (la vôtre ou un modèle partagé) comme point de départ.

![Un tableau de bord personnalisable DefectDojo Pro — la disposition Default Dashboard.](images/pro_dashboard_v2_default.png)

## Comparaison avec la version open source

La version open source de DefectDojo propose un unique [tableau de bord principal](../introduction_dashboard/) intégré, avec un ensemble fixe de cartes de synthèse et de graphiques qu'un superutilisateur peut afficher ou masquer. Il est identique pour tous les utilisateurs.

DefectDojo Pro remplace cette page fixe par des **tableaux de bord personnalisables par utilisateur**. Vous choisissez les widgets qui apparaissent, la façon dont ils sont filtrés, et leur emplacement sur la grille. Vous pouvez créer autant de dispositions nommées que vous le souhaitez, passer de l'une à l'autre, les partager avec votre équipe, et piloter l'ensemble du système depuis l'[API REST](../custom-dashboards-api/) ou un [LLM](../custom-dashboards-llm/).

> **💡 Astuce :** Dans DefectDojo Pro, les **Assets** s'appelaient auparavant des **Produits**, et les **Organisations** s'appelaient auparavant des **Product Types**. L'interface utilise désormais la nouvelle terminologie, mais certains paramètres de widgets sous-jacents utilisent encore les anciens noms — par exemple, la plupart des widgets prennent un `model` valant `finding`, `product`, `engagement` ou `test`. Lorsque cela a une importance, c'est signalé ci-dessous.

## Activation des tableaux de bord personnalisables

Les tableaux de bord personnalisables sont désactivés par défaut. Un superutilisateur peut les activer depuis **Paramètres > Feature Flags**, aussi bien sur les instances Cloud que On-Premise. Voir [Feature Flags](/admin/feature_flags/pro__feature_flags/).

Une fois activée, la page **🏠 Accueil** affiche votre tableau de bord personnalisable, et l'[API REST des tableaux de bord](../custom-dashboards-api/) devient disponible.

> **🔑 Important :** Tant que la fonctionnalité est désactivée, la page d'accueil conserve l'ancien tableau de bord et chaque point de terminaison `/api/v2/dashboards/` renvoie `403 Dashboards 2.0 is not enabled.` L'activer ne modifie **pas** l'accès aux données de qui que ce soit — chaque widget continue de respecter le contrôle d'accès basé sur les rôles de DefectDojo, de sorte que chaque utilisateur ne voit jamais que les Constatations, Assets et autres enregistrements qu'il est autorisé à consulter.

## Concepts fondamentaux

Un tableau de bord personnalisable se construit à partir de quelques éléments simples.

### Dispositions

Une **disposition** (layout) est un tableau de bord nommé : un ensemble de widgets et de leurs positions sur la grille. Chaque disposition vous appartient, et vous pouvez en créer autant que vous le souhaitez — par exemple un tableau « Triage quotidien » et un « Aperçu direction » distinct. Une disposition stocke trois éléments :

- **widgets** — la liste ordonnée des widgets qu'elle contient, chacun avec son propre type, titre et configuration.
- **layout** — l'emplacement et la taille de chaque widget sur la grille.
- **settings** — les options d'affichage au niveau de la disposition.

La première fois que vous ouvrez les tableaux de bord personnalisables, DefectDojo vous donne une copie personnelle du modèle de démarrage **Default Dashboard**, afin que vous ne partiez jamais d'une page vierge.

### Widgets

Un **widget** est un panneau unique sur le tableau de bord. Chaque widget est une instance d'un **type** issu du catalogue (un Count, un Graph, un Top-N leaderboard, etc.), et possède sa propre **configuration** : le **modèle** de données qu'il lit (`finding`, `product`, `engagement` ou `test`), les **filtres** qui le délimitent, ainsi que des options d'affichage propres au type, comme le type de graphique, les couleurs ou le regroupement. Deux widgets du même type avec des filtres différents sont totalement indépendants.

Chaque widget dispose également d'un **intervalle d'actualisation automatique** facultatif (désactivé, 30 secondes, 1 minute, 5 minutes ou 15 minutes) et d'un **titre** modifiable.

### The widget catalog

Le **catalogue** est le menu fixe des types de widgets pris en charge par la plateforme, regroupés en quatre catégories — **Numbers**, **Charts**, **Lists & Feeds** et **Static & Utility**. Lorsque vous ajoutez un widget, vous choisissez son type dans le catalogue. Le catalogue est également accessible via l'[API](../custom-dashboards-api/), ce qui permet aux scripts et aux LLM de découvrir les types de widgets disponibles ainsi qu'une configuration de départ éprouvée pour chacun. Voir [The widget catalog](#the-widget-catalog-1) ci-dessous pour la liste complète.

### La grille

Les widgets sont placés sur une **grille de 12 colonnes**. En mode édition, vous faites glisser les widgets pour les déplacer, et vous faites glisser leur coin inférieur droit pour les redimensionner ; la grille se compacte vers le haut pour combler les espaces vides. Chaque type de widget dispose de tailles minimale et maximale raisonnables afin que les graphiques et les tableaux restent lisibles.

### Partage, clonage et valeurs par défaut

- **Default** — l'une de vos dispositions est votre disposition **par défaut** : celle qui se charge lorsque vous ouvrez la page d'accueil. Vous pouvez changer votre disposition par défaut à tout moment.
- **Clone** — copiez n'importe quelle disposition (l'une des vôtres, ou un modèle partagé) dans votre propre espace comme nouveau point de départ indépendant. Le clonage donne à la copie ses propres widgets, si bien que modifier le clone n'affecte jamais l'original.
- **Share** — publiez l'une de vos dispositions pour toute l'équipe sous forme de **disposition partagée**. Les autres utilisateurs peuvent la voir et la cloner, mais seul un **Maintainer** de l'équipe peut publier, modifier ou annuler le partage d'une disposition partagée. Partager une disposition ne partage que sa *conception* — chaque personne qui la consulte ne voit toujours que les données que ses propres permissions autorisent.
- **Starter & shared templates** — DefectDojo fournit un ensemble de **modèles partagés** sélectionnés que vous pouvez cloner pour prendre une longueur d'avance (voir [Shared templates](#shared-templates) ci-dessous). Le **Default Dashboard** est le modèle de « démarrage » spécial attribué automatiquement aux nouveaux utilisateurs.

## Créer un tableau de bord dans l'interface

### La barre d'outils du tableau de bord

La barre d'outils en haut de la page d'accueil permet de changer de disposition et de les gérer. Elle comprend un **sélecteur de disposition** (avec des badges qui indiquent votre disposition par défaut et les dispositions ou modèles partagés), ainsi que des boutons pour créer une **nouvelle disposition**, ouvrir **Gérer les dispositions**, **actualiser** tous les widgets, et basculer le mode **Édition**.

![La barre d'outils du tableau de bord (mise en évidence) : le sélecteur de disposition, ainsi que Nouvelle disposition, Gérer les dispositions, Actualiser et Édition](images/pro_dashboard_v2_home.png)

### Étape 1 : passer en mode édition

Cliquez sur **Édition** pour déverrouiller le tableau de bord. La grille devient alors déplaçable et redimensionnable, et un bouton **Ajouter un widget** apparaît. Cliquez sur **Terminé** lorsque vous avez fini — le mode édition se désactive également automatiquement lorsque vous changez de disposition.

![Un tableau de bord en mode édition, avec les poignées de déplacement et de redimensionnement](images/pro_dashboard_v2_edit_grid.png)

### Étape 2 : ajouter un widget

En mode édition, cliquez sur **Ajouter un widget** pour ouvrir le sélecteur. Il comporte deux onglets :

- **Par type** — parcourez le catalogue par catégorie (Numbers, Charts, Lists & Feeds, Static & Utility). Chaque carte affiche le nom du widget et une courte description. Sélectionner une carte l'ajoute à la grille et ouvre sa boîte de dialogue de configuration.
- **Depuis le catalogue** — partez d'un widget préconfiguré issu de l'un des modèles partagés (par exemple, le graphique « Constatations par sévérité » du Default Dashboard). Ceux-ci arrivent déjà configurés, et se déposent directement sur la grille.

![La boîte de dialogue Ajouter un widget, onglet Par type](images/pro_dashboard_v2_add_widget.png)

### Étape 3 : configurer le widget

Chaque widget ouvre une boîte de dialogue de configuration adaptée à son type. Les paramètres courants comprennent :

- **Titre** — l'intitulé affiché sur le widget.
- **Modèle** — les enregistrements que le widget lit (Constatation, Asset, Engagement ou Test), le cas échéant.
- **Filtres** — une interface de filtrage intégrée, semblable à celle d'une vue en liste, qui limite le widget exactement aux enregistrements souhaités (par exemple, les Constatations actives de sévérité Critique). Les filtres choisis ici sont les mêmes que ceux utilisés sur la page de liste de cet objet.
- **Intervalle d'actualisation** — la fréquence à laquelle le widget se recharge automatiquement.
- **Options propres au type** — par exemple le type de graphique et la dimension de regroupement pour un Graph, les seuils pour un Gauge, ou la métrique pour un Top-N leaderboard.

![Configuration d'un widget Graph](images/pro_dashboard_v2_widget_config.png)

> **💡 Astuce :** Les données d'un widget respectent toujours vos permissions. Si une disposition partagée comprend un widget « My Work », chaque personne qui la consulte voit *ses propres* affectations et mentions — jamais celles de l'auteur de la disposition.

### Étape 4 : organiser, puis enregistrer

Faites glisser les widgets pour les réorganiser, et faites glisser un coin pour les redimensionner. Utilisez l'icône d'engrenage d'un widget pour le reconfigurer, et l'icône de corbeille pour le supprimer. Les changements de position et de taille sont enregistrés automatiquement au fur et à mesure. Cliquez sur **Terminé** pour quitter le mode édition.

### Gérer les dispositions

La boîte de dialogue **Gérer les dispositions** (le bouton en forme d'engrenage sur la barre d'outils) centralise tout ce qui concerne les dispositions :

- **Vos dispositions** — renommez, définissez comme disposition par défaut, partagez/annulez le partage, clonez ou supprimez chacune des dispositions que vous possédez.
- **Créer une nouvelle disposition** — démarrez une disposition vierge à construire de zéro.
- **Modèles partagés** — parcourez les dispositions sélectionnées et publiées par l'équipe, regroupées par catégorie, et cliquez sur **Utiliser cette disposition** pour en cloner une dans votre propre espace.

![La boîte de dialogue Gérer les dispositions](images/pro_dashboard_v2_manage_layouts.png)

### Shared templates

DefectDojo fournit quatre modèles partagés prêts à l'emploi que vous pouvez cloner comme point de départ :

| Modèle | Objectif |
|----------|---------|
| **Default Dashboard** | La vue d'accueil classique — 12 compteurs en un coup d'œil, des graphiques de sévérité, et les assets les mieux/moins bien notés. C'est le modèle de démarrage attribué automatiquement à chaque nouvel utilisateur. |
| **Priority Layout** | Un tableau axé sur le triage, organisé autour de la priorité et du risque des constatations. |
| **Mitigation Layout** | Un tableau de vitesse de remédiation (tendances de clôture, MTTR/MTTD, ancienneté). |
| **Tool Layout** | Un tableau d'efficacité des scanners, organisé autour des types de tests et de l'activité de scan récente. |

> **💡 Astuce :** Cloner un modèle crée une copie indépendante. Personnalisez le clone librement — vous n'affecterez ni le modèle, ni personne d'autre qui le clone.

### L'état vide

Une disposition toute neuve, sans widget, affiche une invite **« Construisez votre premier tableau de bord »**. Cliquez sur **Ajoutez votre premier widget** pour passer directement en mode édition et commencer à choisir des widgets.

![L'état d'une disposition vide](images/pro_dashboard_v2_empty_state.png)

## The widget catalog

Les tableaux de bord personnalisables sont fournis avec les types de widgets suivants, organisés en quatre catégories. La plupart des widgets lisent l'un des quatre modèles suivants — `finding`, `product` (Assets), `engagement` ou `test` — et sont délimités par les filtres que vous choisissez. Les options de configuration détaillées de chaque widget sont documentées dans le [guide de l'API](../custom-dashboards-api/).

### Numbers

Des métriques en un coup d'œil — compteurs, KPI et jauges.

| Widget | Ce qu'il affiche |
|--------|---------------|
| **Count** | Un nombre unique issu d'une requête filtrée — par ex. « Constatations Critiques ouvertes » ou « Engagements actifs ». Fonctionne avec finding / asset / engagement / test. |
| **KPI / Trend** | Un chiffre clé accompagné de son évolution par rapport à la période précédente, avec une mini-courbe optionnelle. |
| **Gauge** | Un ratio représenté sous forme de jauge en arc — un filtre « univers » comme dénominateur et un filtre « réussite » comme numérateur. À utiliser pour le respect des SLA, le taux d'atténuation ou la couverture de scan, avec des seuils d'alerte/OK configurables. |
| **License Usage** | Le statut d'utilisation de la licence de votre compte, avec une ventilation par signal (taille de la base de données, volume hebdomadaire de constatations, etc.). *Nécessite le rôle Maintainer.* |
| **Scan Coverage** | La proportion d'assets scannés au cours des 30 / 90 / 180 / 365 derniers jours, sous forme de cumul multi-fenêtres. |

### Charts

Visualisations de séries temporelles et de répartitions.

| Widget | Ce qu'il affiche |
|--------|---------------|
| **Graph** | Un graphique généraliste sur n'importe quel modèle et dimension de regroupement — barres, lignes, aires, camembert ou anneau. Par ex. Constatations par sévérité, Constatations par mois. |
| **Sankey** | Un diagramme de flux d'une dimension source vers une dimension cible — par ex. Sévérité → Statut. |
| **Sunburst** | Une ventilation radiale à un ou deux niveaux — par ex. Sévérité, puis Type de test au sein de chaque sévérité. |
| **Risk Matrix** | Une carte de chaleur des constatations croisant probabilité EPSS et risque — sûr en bas à gauche, dangereux en haut à droite. |
| **Priority Histogram** | La distribution des scores de **priorité** des constatations issus du moteur de priorisation, avec regroupement automatique. |
| **Rate by Category** | Un ratio par catégorie (numérateur / dénominateur) — par ex. taux de faux positifs par outil ou taux d'atténuation par asset. |
| **Finding Velocity** | Les constatations créées par rapport aux constatations clôturées dans le temps, indiquant si le backlog augmente ou diminue. |
| **MTTR / MTTD** | Le temps moyen de remédiation et le temps moyen de détection, sous forme de séries temporelles appariées. |
| **Vulnerability Aging** | Les constatations ouvertes regroupées par tranche d'ancienneté (0–30 j / 30–90 j / 90–180 j / 180 j+), empilées par sévérité. |
| **Activity Heatmap** | Un calendrier d'activité quotidienne dans le style GitHub, sur une fenêtre glissante. |
| **Portfolio Treemap** | Des rectangles imbriqués pour un cumul de portefeuille (Organisation → Asset), dimensionnés par nombre et teintés par sévérité. |

### Lists & Feeds

Listes classées, flux et tableaux intégrés.

| Widget | Ce qu'il affiche |
|--------|---------------|
| **Top-N Leaderboard** | Une liste classée selon l'un de deux modes : *aggregate* (les principaux groupes d'une dimension par nombre, par ex. Top 10 des CWE) ou *records* (les enregistrements individuels les mieux classés selon une métrique, par ex. Top 10 des Assets par note). |
| **Embedded Table** | Une vue en liste complète (Constatations, Assets, Engagements, Tests, Acceptations du risque, Organisations ou Types de tests) avec filtres et tri prédéfinis — pagination, tri et export CSV inclus. |
| **Recent Activity** | Un flux défilant des enregistrements les plus récemment mis à jour, cliquables vers leurs pages de détail. |
| **SLA Burndown** | Les constatations proches du dépassement de leur SLA, classées par jours restants, avec des badges de compte à rebours. |
| **My Work** | Votre file personnelle — affectations, mentions et révisions d'acceptation du risque en attente. Toujours limitée à la personne qui consulte le widget. |
| **Saved Reports** | Un accès en un clic à vos modèles de rapport enregistrés. *Nécessite la fonctionnalité Rapports.* |

### Static & Utility

Notes, raccourcis et structure.

| Widget | Ce qu'il affiche |
|--------|---------------|
| **Favorites** | Des liens rapides, choisis par l'utilisateur, vers des pages spécifiques de l'application. |
| **Section Break** | Un séparateur libellé pour regrouper des widgets apparentés sous un intitulé. |
| **Markdown / Notes** | Un panneau de texte enrichi intégré pour des en-têtes, des notes de contexte ou des liens de référence. |
| **Quick Actions** | Des boutons d'action en un clic qui mènent vers une page choisie. |

## Prochaines étapes

- **[Automatiser les tableaux de bord avec l'API](../custom-dashboards-api/)** — découvrez le catalogue de widgets, créez et mettez à jour des dispositions, et récupérez les données des widgets via l'API REST, avec un script complet.
- **[Créer des tableaux de bord avec un LLM](../custom-dashboards-llm/)** — laissez un LLM concevoir et construire des tableaux de bord pour vous (l'API des tableaux de bord a été conçue en pensant aux agents IA).
