---
title: Étiquetage des objets
description: Utilisez les étiquettes pour créer une nouvelle tranche de votre modèle
  de données
draft: false
weight: 2
exclude_search: false
audience: pro
aliases:
- /fr/en/working_with_findings/organizing_engagements_tests/tagging_objects
---

Les étiquettes sont idéales pour regrouper des objets de manière à pouvoir les filtrer en ensembles plus petits et plus faciles à assimiler.  Elles peuvent être utilisées pour indiquer un statut, ou pour créer des ensembles personnalisés de Type de produit, Produits, Engagements ou Constatations dans l'ensemble du modèle de données.

Dans DefectDojo, les étiquettes sont un élément de première classe et sont reconnues comme les facilitateurs
de l'organisation à chaque niveau du modèle de données.

Voici un exemple avec un Produit ayant deux étiquettes et quatre constatations ayant chacune une seule étiquette :

![Exemple général d'utilisation des étiquettes](images/tags-high-level-example.png)

### Formats d'étiquettes

Les étiquettes peuvent être formatées de l'une des manières suivantes :
- ChaîneSansEspaces
- chaine-avec-tirets
- chaine_avec_underscores
- deuxpoints:acceptable

## Gestion des étiquettes (interface Pro)

### Ajout et suppression

Les étiquettes peuvent être gérées des manières suivantes :

1. **Création ou modification de nouveaux objets**

   Lorsqu'un nouvel objet est créé ou modifié via l'interface ou l'API, un champ permet de spécifier
   les étiquettes à définir sur un objet donné.

   ![étiquette](images/tags_product.png)

2. **Lors de l'importation/réimportation de constatations**

  Les étiquettes sont disponibles sur le formulaire d'importation/réimportation, à la fois dans l'interface et via l'API.  Lorsque ce formulaire est soumis, le **Test** sera étiqueté avec `[tag]` et `[daily-import]`.  Si « Apply Tags to Findings » ou « Apply Tags to Endpoints » est sélectionné, ces objets seront également étiquetés.  Les étiquettes offrent la possibilité d'ajouter des détails d'exécution d'automatisation et des informations sur l'outil qui pourraient ne pas être capturées directement dans l'objet Test ou Constatation.

   ![étiquette](images/tags_importscan.png)

3. **Via la modification en masse**

  Lorsque plusieurs constatations sont sélectionnées dans un tableau, vous pouvez utiliser le menu de modification en masse pour modifier les étiquettes associées à plusieurs constatations simultanément.  Notez que cela remplacera toutes les étiquettes au niveau de la constatation par les étiquettes spécifiées ; les étiquettes existantes seront écrasées.

  ![modification en masse des constatations](images/Bulk_Editing_Findings.png)


## Gestion des étiquettes (interface classique / Open Source)

### Ajout et suppression

Les étiquettes peuvent être gérées des manières suivantes :

1. Création ou modification de nouveaux objets

   Lorsqu'un nouvel objet est créé ou modifié via l'interface ou l'API, un champ permet de spécifier
   les étiquettes à définir sur un objet donné. Ce champ est un champ à sélection multiple qui dispose également
   d'une saisie semi-automatique pour faciliter la recherche et l'ajout d'étiquettes existantes. Voici à quoi
   ressemble ce champ sur le Produit de la capture d'écran de la section précédente :

   ![Gestion des étiquettes sur un objet](images/tags-management-on-object.png)

2. Import et réimportation

    Les étiquettes peuvent également être appliquées à un test donné au moment de l'importation ou de la réimportation. C'est un cas d'usage
    très pratique lors de l'importation via l'API avec automatisation, car cela offre l'occasion d'ajouter
    des détails d'exécution d'automatisation et des informations sur l'outil qui pourraient ne pas être capturées
    directement dans l'objet test ou constatation.

    Le champ se présente et se comporte exactement comme sur un objet donné

3. Menu de modification en masse (constatations uniquement)

    Lorsqu'il est nécessaire de mettre à jour plusieurs constatations avec le même ensemble d'étiquettes, le menu de modification en masse peut être
    utilisé pour alléger la tâche.

    Dans l'exemple suivant, supposons que je souhaite mettre à jour les étiquettes des deux constatations portant l'étiquette « tag-group-alpha » avec une nouvelle liste d'étiquettes comme ceci ["tag-group-charlie", "tag-group-delta"].
    Je commencerais par sélectionner les étiquettes à mettre à jour :

    ![Sélection des constatations pour la mise à jour d'étiquettes en masse](images/tags-select-findings-for-bulk-edit.png)

    Une fois qu'une constatation est sélectionnée, un nouveau bouton nommé « Bulk Edit » apparaît. Cliquer sur ce bouton
    fait apparaître un menu déroulant proposant de nombreuses options, mais l'attention se porte ici uniquement sur les étiquettes. Modifiez le
    champ pour qu'il contienne la liste d'étiquettes souhaitée comme suit, puis cliquez sur soumettre

    ![Application des modifications pour la mise à jour d'étiquettes en masse](images/tags-bulk-edit-submit.png)

    Les étiquettes des constatations sélectionnées seront mises à jour avec ce qui a été spécifié dans le champ des étiquettes
    du menu de modification en masse

    ![Mise à jour d'étiquettes en masse terminée](images/tags-bulk-edit-complete.png)

## Héritage des étiquettes

**Remarque sur l'interface Pro : bien que l'héritage des étiquettes puisse être configuré via l'interface Pro, les étiquettes héritées ne peuvent actuellement être consultées et filtrées que via l'interface classique ou l'API.**

Lorsque l'héritage des étiquettes est activé, les étiquettes appliquées à un Produit donné seront automatiquement appliquées à tous les objets sous ce Produit dans la [hiérarchie des produits](/asset_modelling/os_hierarchy/product_hierarchy/).

### Configuration

L'héritage des étiquettes peut être activé aux niveaux de portée suivants :
- Portée globale
  - Chaque Produit du système entier commencera à appliquer des étiquettes à tous les objets enfants (Engagements, Tests et Constatations)
  - Ceci est configuré dans les Paramètres système
- Portée du produit
  - Seul le Produit sélectionné commencera à appliquer des étiquettes à tous les objets enfants (Engagements, Tests et Constatations)
  - Ceci est configuré sur la page de création/modification du Produit

### Comportements

Lorsque l'héritage des étiquettes est activé, les étiquettes standard peuvent être ajoutées et supprimées des objets de la manière habituelle.
Cependant, les étiquettes héritées ne peuvent pas être supprimées d'un objet enfant sans les supprimer de l'objet parent.
Voir l'exemple suivant d'ajout d'une étiquette « test_only_tag » à l'objet Test et d'une étiquette « engagement_only_tag » à l'Engagement.

![Exemple d'étiquettes héritées](images/tags-inherit-exmaple.png)

Lorsque des mises à jour sont effectuées sur la liste d'étiquettes d'un Produit, les mêmes modifications sont appliquées de manière asynchrone à tous les objets au sein du Produit. La durée de cette tâche est directement corrélée au nombre d'objets contenus dans une constatation.

**Open Source :** Si les modifications d'étiquettes ne sont pas observées dans un délai raisonnable, consultez les journaux du worker celery pour identifier l'origine d'éventuels problèmes.


### Filtrage par étiquettes (interface classique)

Les étiquettes peuvent être filtrées de nombreuses manières, à la fois via l'interface et l'API. Par exemple, voici un extrait
des filtres de constatation :

![Extrait des filtres de constatation](images/tags-finding-filter-snippet.png)

Il existe dix champs liés aux étiquettes :

 - Tags : filtre sur toutes les étiquettes attachées à une constatation donnée
   - Exemples :
     - La constatation sera renvoyée
       - Étiquettes de la constatation : ["A", "B", "C"]
       - Requête de filtre : "B"
     - La constatation *ne* sera *pas* renvoyée
       - Étiquettes de la constatation : ["A", "B", "C"]
       - Requête de filtre : "F"
 - Not Tags : filtre sur toutes les étiquettes qui *ne* sont *pas* attachées à une constatation donnée
   - Exemples :
     - La constatation sera renvoyée
       - Étiquettes de la constatation : ["A", "B", "C"]
       - Requête de filtre : "F"
     - La constatation *ne* sera *pas* renvoyée
       - Étiquettes de la constatation : ["A", "B", "C"]
       - Requête de filtre : "B"
 - Tag Name Contains : filtre sur toutes les étiquettes qui contiennent tout ou partie de la requête dans la constatation donnée
   - Exemples :
     - La constatation sera renvoyée
       - Étiquettes de la constatation : ["Alpha", "Beta", "Charlie"]
       - Requête de filtre : "et" (partie de "Beta")
     - La constatation *ne* sera *pas* renvoyée
       - Étiquettes de la constatation : ["Alpha", "Beta", "Charlie"]
       - Requête de filtre : "meg" (partie de "Omega")
 - Not Tags : filtre sur toutes les étiquettes qui *ne* contiennent *pas* tout ou partie de la requête dans la constatation donnée
   - Exemples :
     - La constatation sera renvoyée
       - Étiquettes de la constatation : ["Alpha", "Beta", "Charlie"]
       - Requête de filtre : "meg" (partie de "Omega")
     - La constatation *ne* sera *pas* renvoyée
       - Étiquettes de la constatation : ["Alpha", "Beta", "Charlie"]
       - Requête de filtre : "et" (partie de "Beta")

Pour les six autres filtres d'étiquettes, ils suivent les mêmes règles que « Tags » et « Not Tags » ci-dessus,
mais à différents niveaux du modèle de données :

 - Tags (Test) : filtre sur toutes les étiquettes attachées au Test d'une constatation donnée
 - Not Tags (Test) : filtre sur toutes les étiquettes qui *ne* sont *pas* attachées au Test d'une constatation donnée
 - Tags (Engagement) : filtre sur toutes les étiquettes attachées à l'Engagement d'une constatation donnée
 - Not Tags (Engagement) : filtre sur toutes les étiquettes qui *ne* sont *pas* attachées à l'Engagement d'une constatation donnée
 - Tags (Product) : filtre sur toutes les étiquettes attachées au Produit d'une constatation donnée
 - Not Tags (Product) : filtre sur toutes les étiquettes qui *ne* sont *pas* attachées au Produit d'une constatation donnée
