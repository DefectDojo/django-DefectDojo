---
title: Note de santé du Produit
description: Comment DefectDojo calcule la Note de santé d'un Produit
aliases:
- /fr/en/working_with_findings/organizing_engagements_tests/product_health_grade
---

DefectDojo peut calculer une note pour vos Produits en fonction du nombre de Constatations qu'ils contiennent. Les notes sont classées de A \- F.

Notez que seules les Constatations Actives \& Vérifiées contribuent à la Note d'un Produit \- les Constatations non vérifiées n'ont aucun impact.

## Calcul de la Note du Produit

Chaque Note de Produit commence à 100 (sans Constatations).

Le calcul de la note commence par l'examen du niveau de **Sévérité** le plus élevé d'une Constatation dans un Produit, et réduit la Santé du Produit à un niveau de base.

| **Niveau de Sévérité le plus élevé d'une Constatation** | **Note maximale** |
| --- | --- |
| **Critique** | **40** |
| **Élevée** | **60** |
| **Moyenne** | **80** |
| **Faible** | **95** |

Des points supplémentaires sont ensuite déduits de la Note pour chaque Constatation additionnelle :

| **Niveau de Sévérité d'une Constatation additionnelle** | **Réduction de la Note** |
| --- | --- |
| **Critique** | **5** |
| **Élevée** | **3** |
| **Moyenne** | **2** |
| **Faible** | **1** |
