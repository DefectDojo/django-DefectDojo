---
title: Étiqueter les objets
description: Utilisez les Étiquettes pour créer une nouvelle vue de votre modèle de
  données
draft: false
weight: 2
exclude_search: false
audience: opensource
---

Les Étiquettes sont idéales pour regrouper des objets de manière à pouvoir les filtrer en ensembles plus petits et plus faciles à traiter.  Elles peuvent être utilisées pour indiquer un statut, ou pour créer des ensembles personnalisés d'Organisations, d'Assets, d'Engagements ou de Constatations à travers le modèle de données.

Dans DefectDojo, les étiquettes sont un concept de premier plan et sont reconnues comme les facilitateurs
de l'organisation à chaque niveau du modèle de données.

Voici un exemple avec un Asset ayant deux étiquettes et quatre constatations ayant chacune une seule étiquette :

![High level example of usage with tags](images/tags-high-level-example.png)

### Formats d'étiquette

Les étiquettes peuvent être formatées de l'une des manières suivantes :
- ChaîneSansEspaces
- chaine-avec-tirets
- chaine_avec_underscores
- deuxpoints:acceptable

## Gestion des étiquettes

### Ajout et suppression

Les étiquettes peuvent être gérées des manières suivantes :

1. Création ou modification de nouveaux objets

   Lorsqu'un nouvel objet est créé ou modifié via l'UI ou l'API, un champ permet de spécifier
   les étiquettes à définir sur cet objet. Ce champ est un champ à sélection multiple qui dispose également
   d'une saisie semi-automatique pour faciliter la recherche et l'ajout d'étiquettes existantes. Voici à quoi ressemble le champ
   sur l'Asset de la capture d'écran de la section précédente :

   ![Tag management on an object](images/tags-management-on-object.png)

2. Importation et réimportation

    Les étiquettes peuvent également être appliquées à un test donné au moment de l'importation ou de la réimportation. C'est un cas d'usage très
    pratique lors de l'importation via l'API avec de l'automatisation, car cela permet d'ajouter
    des détails d'exécution d'automatisation et des informations sur l'outil qui ne seraient pas capturées directement dans l'objet test
    ou constatation.

    Le champ se présente et se comporte exactement comme sur un objet donné

3. Menu Modification en masse (Constatations uniquement)

    Lorsqu'il faut mettre à jour de nombreuses Constatations avec le même ensemble d'étiquettes, le menu de modification en masse peut être
    utilisé pour alléger la tâche.

    Dans l'exemple suivant, supposons que je veuille mettre à jour les étiquettes des deux constatations ayant l'étiquette "tag-group-alpha" avec une nouvelle liste d'étiquettes comme ceci ["tag-group-charlie", "tag-group-delta"].
    Je sélectionnerais d'abord les étiquettes à mettre à jour :

    ![Select findings for bulk edit tag update](images/tags-select-findings-for-bulk-edit.png)

    Une fois une constatation sélectionnée, un nouveau bouton apparaît avec le nom "Bulk Edit". Cliquer sur ce bouton
    fait apparaître un menu déroulant avec de nombreuses options, mais on se concentre ici uniquement sur les étiquettes. Mettez à jour le
    champ avec la liste d'étiquettes souhaitée comme suit, puis cliquez sur soumettre

    ![Apply changes for bulk edit tag update](images/tags-bulk-edit-submit.png)

    Les étiquettes des Constatations sélectionnées seront mises à jour avec ce qui a été spécifié dans le champ des étiquettes
    du menu de modification en masse

    ![Completed bulk edit tag update](images/tags-bulk-edit-complete.png)

## Héritage des étiquettes

Lorsque l'Héritage des étiquettes est activé, les étiquettes appliquées à un Asset donné sont automatiquement appliquées à tous les objets sous les Assets dans la [Hiérarchie des Assets](/asset_modelling/os_hierarchy/os__asset_hierarchy/).

### Configuration

L'Héritage des étiquettes peut être activé aux niveaux de portée suivants :
- Portée globale
  - Chaque Asset, à l'échelle du système, commence à appliquer des étiquettes à tous les objets enfants (Engagements, Tests et Constatations)
  - Ceci se configure dans les Paramètres système
- Portée Asset
  - Seul l'Asset sélectionné commence à appliquer des étiquettes à tous les objets enfants (Engagements, Tests et Constatations)
  - Ceci se configure sur la page de création/modification de l'Asset

### Comportements

Lorsque l'Héritage des étiquettes est activé, les Étiquettes standard peuvent être ajoutées à ou supprimées des objets de la manière habituelle.
Cependant, les étiquettes héritées ne peuvent pas être supprimées d'un objet enfant sans les supprimer de l'objet parent
Voir l'exemple suivant, d'ajout d'une étiquette "test_only_tag" à l'objet Test et d'une étiquette "engagement_only_tag" à l'Engagement.

![Example of inherited tags](images/tags-inherit-exmaple.png)

Lorsque des mises à jour sont effectuées sur la liste d'étiquettes d'un Asset, les mêmes modifications sont appliquées à tous les objets de l'Asset de manière asynchrone. La durée de cette tâche est directement corrélée au nombre d'objets contenus dans une constatation.

**Open-Source :** Si les modifications d'étiquettes ne sont pas observées dans un délai raisonnable, consultez les journaux du worker celery pour identifier l'origine d'éventuels problèmes.


### Filtrage par étiquettes (UI classique)

Les étiquettes peuvent être filtrées de nombreuses manières, à la fois via l'UI et l'API. Par exemple, voici un extrait
des filtres de Constatation :

![Snippet of the finding filters](images/tags-finding-filter-snippet.png)

Il existe dix champs liés aux étiquettes :

 - Tags : filtre sur toute étiquette rattachée à une Constatation donnée
   - Exemples :
     - La Constatation sera retournée
       - Étiquettes de la Constatation : ["A", "B", "C"]
       - Requête de filtre : "B"
     - La Constatation ne sera *pas* retournée
       - Étiquettes de la Constatation : ["A", "B", "C"]
       - Requête de filtre : "F"
 - Not Tags : filtre sur toute étiquette *non* rattachée à une Constatation donnée
   - Exemples :
     - La Constatation sera retournée
       - Étiquettes de la Constatation : ["A", "B", "C"]
       - Requête de filtre : "F"
     - La Constatation ne sera *pas* retournée
       - Étiquettes de la Constatation : ["A", "B", "C"]
       - Requête de filtre : "B"
 - Tag Name Contains : filtre sur toute étiquette contenant tout ou partie de la requête dans la Constatation donnée
   - Exemples :
     - La Constatation sera retournée
       - Étiquettes de la Constatation : ["Alpha", "Beta", "Charlie"]
       - Requête de filtre : "et" (partie de "Beta")
     - La Constatation ne sera *pas* retournée
       - Étiquettes de la Constatation : ["Alpha", "Beta", "Charlie"]
       - Requête de filtre : "meg" (partie de "Omega")
 - Not Tags : filtre sur toute étiquette qui ne contient *pas* tout ou partie de la requête dans la Constatation donnée
   - Exemples :
     - La Constatation sera retournée
       - Étiquettes de la Constatation : ["Alpha", "Beta", "Charlie"]
       - Requête de filtre : "meg" (partie de "Omega")
     - La Constatation ne sera *pas* retournée
       - Étiquettes de la Constatation : ["Alpha", "Beta", "Charlie"]
       - Requête de filtre : "et" (partie de "Beta")

Pour les six autres filtres d'étiquettes, ils suivent les mêmes règles que "Tags" et "Not Tags" ci-dessus,
mais à différents niveaux du modèle de données :

 - Tags (Test) : filtre sur toute étiquette rattachée au Test d'une Constatation donnée
 - Not Tags (Test) : filtre sur toute étiquette *non* rattachée au Test d'une Constatation donnée
 - Tags (Engagement) : filtre sur toute étiquette rattachée à l'Engagement d'une Constatation donnée
 - Not Tags (Engagement) : filtre sur toute étiquette *non* rattachée à l'Engagement d'une Constatation donnée
 - Tags (Asset) : filtre sur toute étiquette rattachée à l'Asset d'une Constatation donnée
 - Not Tags (Asset) : filtre sur toute étiquette *non* rattachée à l'Asset d'une Constatation donnée
