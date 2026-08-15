---
title: Aperçu des métriques Pro
description: Comment exploiter les métriques dans DefectDojo Pro
audience: pro
weight: 2
---

L'interface de DefectDojo Pro propose divers tableaux de bord de métriques pour vous aider à visualiser votre posture de sécurité actuelle. Chaque tableau de bord permet aux parties prenantes des différents niveaux de l'organisation de prendre des décisions éclairées sans avoir à interpréter des données brutes ou à parcourir les Constatations une par une. Ces tableaux de bord comprennent :
* [Aperçu de la direction](/metrics_reports/pro_metrics/pro__executive_insights/#main-content)
* [Aperçu des priorités](/metrics_reports/pro_metrics/pro__priority_insights/#main-content)
* [Aperçu du programme](/metrics_reports/pro_metrics/pro__program_insights/#main-content)
* [Aperçu de la remédiation](/metrics_reports/pro_metrics/pro__remediation_insights/#main-content)
* [Aperçu des outils](/metrics_reports/pro_metrics/pro__tool_insights/#main-content)

![Metrics overview](images/metrics_image1.png)

## Fonctionnalités des métriques

Avant de détailler chaque tableau de bord en particulier, il convient de passer en revue certains points communs à tous les tableaux de bord.

### Filtrage

Toutes les métriques peuvent être filtrées par période, Organisation, Asset et Étiquette. Une fois le filtre ajusté comme souhaité, il faut cliquer sur **Appliquer le filtre** pour que le filtre prenne effet. Si vous souhaitez exporter en PDF l'ensemble des graphiques, tableaux et courbes du tableau de bord tel qu'il est actuellement filtré, cliquez sur **Exporter en PDF**. 

La période de filtrage est limitée à l'année écoulée, mais peut sinon être ajustée pour couvrir les 7, 14, 30, 90 ou 180 derniers jours.

Notez que les paramètres de filtre sont répercutés dans l'URL, ce qui vous permet de mettre en favoris plusieurs pages avec différents paramètres de filtre.  Cela peut être utile pour une consultation rapide, ou pour générer systématiquement un type de rapport particulier.

### Sous-menus 

Chaque graphique dispose d'un menu kebab ⋮ en haut à droite de chaque vue, avec les fonctionnalités suivantes :
* **Forcer l'actualisation** — Actualise manuellement les données pour intégrer toute nouvelle mise à jour. 
* **Agrandir le graphique** — Ouvre le même graphique dans une fenêtre modale agrandie.
* **Télécharger le graphique en SVG** — Télécharge le graphique sous forme de fichier SVG.
* **Afficher sous forme de tableau** — Affiche les données du graphique sous forme de tableau.
    * Chaque colonne du tableau peut être basculée pour s'afficher par ordre croissant ou décroissant en cliquant dessus. Vous pouvez également télécharger chaque tableau.

![Kebab menu contents](images/metrics_image2.png)

### Accès

La section Métriques ne présente que les données des Organisations et des Assets que chaque Utilisateur est autorisé à consulter. Un Utilisateur dont l'accès est limité à un seul Asset ne pourra voir les métriques que pour cet Asset en particulier ; s'il n'a pas accès aux autres Assets de l'Organisation parente, les données de ces autres Assets n'apparaîtront pas dans les métriques. 

### Consultation des données dans les graphiques

L'axe des X des graphiques linéaires représente toujours la période actuellement filtrée. Survoler un graphique linéaire avec le curseur fait apparaître une fenêtre modale indiquant le nombre correspondant sur l'axe des Y à ce moment précis. 

![Graph pop-up modal](images/metrics_image3.png)

### Activer/désactiver l'affichage des résultats

Les Utilisateurs peuvent activer ou désactiver l'affichage de certaines catégories de Constatations dans le graphique en cliquant sur leur couleur/nom respectif en haut de chaque graphique. 

Par exemple, dans le graphique des Constatations actives par sévérité ci-dessous, si vous souhaitez uniquement voir les Constatations de sévérité Élevée ou Critique, cliquez sur Moyenne, Faible et Info en haut pour retirer ces résultats du graphique. Cliquez à nouveau sur Moyenne, Faible et Info pour les faire réapparaître. 

![Toggling graph results gif](images/metrics_image4.gif)
