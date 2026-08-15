---
title: Activer la déduplication
description: Comment activer la déduplication au niveau du Produit ou de l'Engagement
weight: 2
audience: pro
aliases:
- /fr/en/working_with_findings/finding_deduplication/enabling_product_deduplication
---

La déduplication peut être appliquée à l'échelle d'un Produit, ou limitée plus étroitement à un seul Engagement.

## Déduplication pour les Produits

1. Accédez à la page Paramètres système : **Paramètres > Système > ⚙️ Paramètres système** dans la barre latérale (**Paramètres > Paramètres Pro > Paramètres système** sur les instances utilisant encore l'ancienne disposition des menus).

![image](images/enabling_product-level_deduplication.png)

2. La carte **Paramètres de déduplication et des constatations** se trouve en haut de la page **Paramètres système**.

![image](images/enabling_product-level_deduplication_2.png)

### Activer la déduplication des constatations

**Activer la déduplication des constatations** active l'Algorithme de déduplication pour toutes les Constatations. Une fois activée, la Déduplication s'exécute à chaque import suivant — DefectDojo compare les Constatations importées à celles déjà présentes dans le Produit de destination et marque les doublons selon votre configuration.

### Supprimer les constatations en double

**Supprimer les constatations en double**, combiné au champ **Nombre maximal de doublons**, limite le nombre de Constatations en double conservées par DefectDojo. Lorsque cette option est activée, une tâche en arrière-plan élague périodiquement les doublons excédentaires afin que chaque Constatation d'origine ne conserve pas plus que le nombre configuré dans **Nombre maximal de doublons**. Les doublons les plus anciens sont supprimés en premier.

## Déduplication pour les Engagements

Plutôt que de dédupliquer sur l'ensemble d'un Produit, vous pouvez limiter la Déduplication à un seul Engagement.

### Ouvrir le formulaire d'Engagement

* **Pour un nouvel Engagement :** ouvrez le sous-menu **📥 Engagements** dans la barre latérale et cliquez sur **+ Nouvel Engagement**.

![image](images/enabling_deduplication_within_an_engagement.png)

* **Pour un Engagement existant (depuis la page Tous les Engagements) :** ouvrez le menu **⋮** de l'Engagement et sélectionnez **Modifier l'Engagement**.

![image](images/enabling_deduplication_within_an_engagement_2.png)

* **Pour un Engagement existant (depuis la page de l'Engagement) :** ouvrez le menu **⚙️ Roue dentée** dans le coin supérieur droit de la page et sélectionnez **Modifier l'Engagement**.

![image](images/enabling_deduplication_within_an_engagement_3.png)

### Compléter le formulaire d'Engagement

1. Dans le formulaire d'Engagement, repérez la case à cocher ☐ **Isoler la déduplication des autres Engagements**. Elle apparaît au-dessus du panneau **Champs facultatifs +**.
2. Cochez la case pour limiter la Déduplication à cet Engagement.
3. Soumettez le formulaire.

Lorsque cette option est activée, les Constatations de cet Engagement ne seront dédupliquées qu'avec d'autres Constatations du même Engagement. Les Constatations des autres Engagements du même Produit sont ignorées par l'Algorithme de déduplication.

![image](images/enabling_deduplication_within_an_engagement_4.png)
