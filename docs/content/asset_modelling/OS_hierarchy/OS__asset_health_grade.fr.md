---
title: Note de santé de l'Actif
description: Comment DefectDojo calcule la Note de santé d'un Actif
weight: 7
audience: opensource
aliases:
- /fr/asset_modelling/os_hierarchy/product_health_grade/
- /fr/en/asset_modelling/os_hierarchy/product_health_grade/
---

DefectDojo peut calculer une note pour vos Actifs en fonction du nombre de Constatations qu'ils contiennent. Les notes vont de A à F.

Notez que seules les Constatations Actives et Vérifiées contribuent à la note d'un Actif : les Constatations non vérifiées n'ont aucun impact.

*La note de santé de chaque Actif (A à F) apparaît à côté de son nom dans la liste des Actifs.*

![Notes de santé des Actifs affichées à côté de chaque Actif dans la liste des Actifs](images/asset-health-grade.png)

## Calcul de la note d'un Actif

Chaque note d'Actif commence à 100 (sans Constatations).

Le calcul de la note commence par examiner le niveau de **Sévérité** le plus élevé d'une Constatation dans un Actif, puis réduit la santé de l'Actif à un niveau de base.

| **Niveau de Sévérité le plus élevé d'une Constatation** | **Note maximale** |
| --- | --- |
| **Critique** | **40** |
| **Élevée** | **60** |
| **Moyenne** | **80** |
| **Faible** | **95** |

Des points supplémentaires sont ensuite déduits de la note pour chaque Constatation additionnelle :

| **Niveau de Sévérité d'une Constatation additionnelle** | **Réduction de la note** |
| --- | --- |
| **Critique** | **5** |
| **Élevée** | **3** |
| **Moyenne** | **2** |
| **Faible** | **1** |
