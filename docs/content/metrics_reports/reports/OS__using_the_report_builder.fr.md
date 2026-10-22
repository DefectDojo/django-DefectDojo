---
title: Utilisation du générateur de rapports
description: Créez, exécutez et récupérez un rapport personnalisé dans DefectDojo
  open source
draft: false
audience: opensource
weight: 24
slug: using-the-report-builder
aliases:
- /fr/en/share_your_findings/pro_reports/working_with_generated_reports
- /fr/metrics_reports/reports/working_with_generated_reports
---

Le générateur de rapports de DefectDojo vous permet d'assembler un rapport personnalisé à partir d'un ensemble de widgets de contenu, de l'exécuter et d'exporter le résultat (par exemple, en l'imprimant au format PDF). Les rapports personnalisés peuvent résumer les Constatations ou les Points de terminaison que vous souhaitez partager avec un public externe, et peuvent inclure une image de marque et du texte standard.

> **Note :** Dans DefectDojo open source, vous créez un rapport, vous l'exécutez et vous récupérez son résultat de manière ponctuelle. Les mises en page de rapport (modèles) et le rapport généré ne sont **pas enregistrés** dans la version open source. Pour réutiliser une mise en page, vous devez la reconstruire dans le générateur de rapports. Pour enregistrer des Thèmes, des Blocs et des Modèles réutilisables, et pour conserver un historique persistant des rapports générés, consultez le [Générateur de rapports](../report-builder/) de DefectDojo Pro.

## Ouverture du générateur de rapports

Le générateur de rapports peut être ouvert depuis la page **📄 Rapports** de la barre latérale.

![image](images/Using_the_Report_Builder.png)

La page du générateur de rapports est organisée en deux colonnes. La colonne de gauche **Format du rapport** est l'endroit où vous concevez votre rapport, à l'aide des widgets de la colonne de droite **Widgets disponibles**.

![image](images/Using_the_Report_Builder_2.png)

## Étape 1 : Définir les options du rapport

![image](images/Using_the_Report_Builder_3.png)

Dans la section Options du rapport, vous pouvez effectuer les actions suivantes :

* Définir un **Nom du rapport** pour le rapport
* Inclure les **Notes de constatation** créées par les utilisateurs dans le rapport
* Inclure les **Images de constatation** dans le rapport
* Charger une **Image** d'en-tête pour le rapport

### Sélectionner une image d'en-tête pour votre rapport

Pour ajouter une image en haut de votre rapport, cliquez sur le bouton **Choose File** et téléchargez une image dans DefectDojo.

L'image sera automatiquement redimensionnée pour s'adapter au document, et s'affichera directement au-dessus de votre **Nom du rapport**.

![image](images/Using_the_Report_Builder_4.png)

## Étape 2 : Ajouter du contenu à l'aide de widgets

Une fois que vous avez défini les options de votre rapport, vous pouvez commencer à concevoir votre rapport à l'aide des widgets de DefectDojo.

Les widgets sont des éléments de contenu d'un rapport que vous ajoutez en les faisant glisser et en les déposant dans la colonne **Format du rapport**. Le rapport final sera généré en fonction de la position de chaque widget, le **Nom du rapport** et l'**Image d'en-tête** s'affichant en haut.

* Les éléments de votre rapport peuvent être réorganisés en faisant glisser et en déposant vos widgets dans un nouvel ordre.
* Pour retirer un widget d'un rapport, cliquez dessus et faites-le glisser vers la colonne de droite.
* Les widgets peuvent également être réduits en cliquant sur l'en-tête gris, pour faciliter la navigation dans le générateur de rapports.
* Le widget Constatations, le widget WYSIWYG et le widget Points de terminaison peuvent chacun être utilisés plusieurs fois.

Pour plus d'informations sur les widgets de rapport, consultez l'[Index des widgets de rapport](./#report-widget-index).

## Étape 3 : Exécuter et afficher le rapport

Une fois que vous avez terminé de créer votre rapport, vous pouvez le générer en cliquant sur le bouton vert **Run** au bas de la section **Format du rapport**.

DefectDojo génère le rapport à partir des widgets que vous avez assemblés. Une fois la génération terminée, vous pouvez consulter le rapport HTML obtenu dans votre navigateur.

![image](images/Using_the_Report_Builder_14.png)

Un rapport généré est un instantané pris à un moment précis : il reflète les données présentes dans DefectDojo au moment de son exécution et ne se met pas à jour automatiquement lorsque vos données changent.

## Étape 4 : Exporter le rapport

Les rapports sont conçus pour pouvoir être exportés ou imprimés facilement.

La méthode la plus simple consiste à imprimer au format PDF. Avec le rapport HTML ouvert, ouvrez une boîte de dialogue **Impression** dans votre navigateur et définissez **Enregistrer au format PDF** comme **Destination d'impression**.

![image](images/Using_the_Report_Builder_15.png)

## Suggestions de mise en forme du rapport

* Les sections WYSIWYG peuvent être utilisées pour contextualiser ou résumer les listes de constatations. Envisagez d'utiliser ce widget tout au long de votre rapport, entre les widgets Constatations ou Points de terminaison vulnérables.

## Index des widgets de rapport

### Widget Page de couverture

Le widget Page de couverture vous permet de définir un titre, un sous-titre et des métadonnées supplémentaires pour votre rapport. Vous ne pouvez avoir qu'une seule Page de couverture par rapport.

![image](images/Using_the_Report_Builder_5.png)

### Widget Résumé exécutif

Le widget Résumé exécutif est destiné à résumer votre rapport en un coup d'œil. Il contient un titre (par défaut « Executive Summary ») ainsi qu'une zone de texte pouvant contenir toutes les informations que vous jugez nécessaires pour résumer le rapport.

![image](images/Using_the_Report_Builder_6.png)

Vous pouvez également **Inclure les SLA** dans votre résumé exécutif. Pour ajouter des images, une mise en forme, ou tout élément allant au-delà du texte brut, envisagez d'ajouter un **widget de contenu WYSIWYG** immédiatement après le résumé exécutif.

* Vous ne pouvez avoir qu'un seul Résumé exécutif par rapport.
* Si votre rapport contient plusieurs configurations de SLA (par exemple, vous avez des Constatations provenant de Produits distincts, chacun ayant ses propres normes de SLA), chaque configuration de SLA sera répertoriée sur le Résumé exécutif sous la forme d'une ligne distincte.

### Widget Sévérités

Étant donné que chaque organisation a ses propres définitions pour chaque niveau de sévérité, le widget Sévérités vous permet de définir les niveaux de sévérité utilisés dans votre rapport, afin d'en faciliter la compréhension.

![image](images/Using_the_Report_Builder_7.png)

### Widget Table des matières

Le widget Table des matières crée une liste de chaque Constatation présente dans votre rapport, pour un accès plus rapide à des Constatations spécifiques. La table des matières crée un titre distinct pour chaque niveau de sévérité présent dans le rapport. Chaque Constatation répertoriée dans la table des matières comporte un lien d'ancrage permettant d'accéder rapidement à la Constatation dans le rapport.

![image](images/Using_the_Report_Builder_8.png)

* Vous pouvez ajouter une section de **Contenu personnalisé**, qui ajoutera du texte sous le titre.
* Vous pouvez charger une image dans la Table des matières en cliquant sur le bouton **Choose File** à côté de la ligne **Image**. L'image chargée s'affichera directement au-dessus du titre sélectionné. Les images seront redimensionnées pour s'adapter au document.

### Widget de contenu WYSIWYG

Le widget WYSIWYG (What You See Is What You Get, c'est-à-dire « ce que vous voyez est ce que vous obtenez ») peut être utilisé pour ajouter une section contenant du texte et des images dans votre rapport. Plusieurs exemplaires de ce widget peuvent être ajoutés pour apporter du contexte à d'autres sections de votre rapport.

![image](images/Using_the_Report_Builder_9.png)

* Le contenu WYSIWYG peut inclure un titre facultatif.
* Des images peuvent être ajoutées à un widget WYSIWYG en les faisant glisser et en les déposant directement dans la zone **Content**. Les images insérées dans la zone Content s'afficheront à leur pleine résolution.
* Vous pouvez ajouter plusieurs widgets WYSIWYG à un rapport.

### Widget Constatations

Le widget Constatations fournit une liste et un résumé de chaque Constatation que vous souhaitez inclure dans votre rapport. Vous pouvez définir la portée des Constatations à inclure à l'aide de filtres.

Le widget Constatations est divisé en deux sections. La section supérieure contient une liste de filtres permettant de déterminer les Constatations à inclure, et la section inférieure contient la liste des Constatations résultant de l'application des filtres.

Pour appliquer des filtres à votre widget Constatations, définissez les paramètres de filtre et cliquez sur le bouton **Apply Filter** en bas. Vous pouvez prévisualiser les résultats de votre filtre en consultant la liste des Constatations située sous la section Filtres.

![image](images/Using_the_Report_Builder_10.png)

* Comme pour les widgets, la section Filtres peut être développée ou réduite en cliquant sur son en-tête gris.
* Vous pouvez ajouter plusieurs widgets Constatations distincts à votre rapport, avec des paramètres de filtre différents, si vous souhaitez que le rapport contienne plusieurs listes de Constatations.
* Seules les Constatations que vous êtes autorisé à consulter sont incluses dans ces listes, conformément au contrôle d'accès basé sur les rôles.

#### Exemple de liste de constatations générée

![image](images/Using_the_Report_Builder_11.png)

### Widget Points de terminaison vulnérables

Le widget Points de terminaison vulnérables est similaire au widget Constatations. Vous pouvez utiliser ce widget pour répertorier toutes les Constatations pour des Points de terminaison spécifiques, et trier la liste des Constatations par Point de terminaison plutôt que par niveau de sévérité.

Le widget **Points de terminaison vulnérables** répertorie chaque Constatation active pour les Points de terminaison sélectionnés. Plutôt que de créer une liste unique de Constatations non triées, cette fonctionnalité les sépare selon leur contexte de Point de terminaison.

Comme pour le widget Constatations, le widget Points de terminaison vulnérables est divisé en une section Filtres et une liste des Points de terminaison résultant des paramètres de filtre.

![image](images/Using_the_Report_Builder_12.png)

Sélectionnez ici les paramètres des Points de terminaison que vous souhaitez inclure, puis cliquez sur le bouton **Apply Findings** en bas. Vous pouvez prévisualiser les résultats de votre filtre en consultant la liste des Points de terminaison située sous la section Filtres.

* Vous pouvez ajouter plusieurs widgets Points de terminaison vulnérables distincts à votre rapport, avec des paramètres de filtre différents, si vous souhaitez que le rapport contienne plusieurs listes.
* Seules les Constatations que vous êtes autorisé à consulter sont incluses dans ces listes, conformément au contrôle d'accès basé sur les rôles.

### Widget ---- (séparateur)

Ce widget affiche une ligne horizontale gris clair pour séparer les sections.

![image](images/Using_the_Report_Builder_13.png)
