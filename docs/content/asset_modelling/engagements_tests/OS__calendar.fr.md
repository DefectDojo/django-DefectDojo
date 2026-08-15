---
title: Calendrier
description: Comment utiliser le Calendrier dans DefectDojo Pro
audience: opensource
weight: 9
---

Le Calendrier de DefectDojo fournit une vue chronologique centralisée de tous les Engagements et Tests ayant des dates de début et de fin définies, permettant aux Utilisateurs de comprendre rapidement l'activité de test à travers les Produits, d'identifier les chevauchements de planification, et de naviguer directement vers les objets associés.

Lorsqu'un Utilisateur crée un Engagement ou un Test et définit des dates de début et de fin, une entrée correspondante est automatiquement ajoutée au Calendrier. Les entrées apparaissent à toutes les dates depuis la date de début définie jusqu'à la date de fin définie incluse.

## Accéder au Calendrier

La page Calendrier est accessible via le bouton Calendrier dans la barre latérale.

![image](images/OSC_ss3.png)

## Visibilité et permissions

### Visibilité

La page Calendrier comprend des filtres en haut et une grille de calendrier mensuelle en dessous. Utilisez les commandes de navigation au-dessus du Calendrier pour passer d'un mois à l'autre.

La vue mensuelle s'affiche sous la forme d'une grille fixe de six semaines, commençant par la semaine contenant le premier jour du mois sélectionné.

Les entrées visibles dans le Calendrier peuvent être filtrées selon le type d'objet (Engagements ou Tests) et le responsable de test, défini dans les paramètres de l'Engagement ou du Test. Après avoir sélectionné les critères de filtre, cliquez sur Appliquer pour actualiser la vue du Calendrier.

Un seul type d'objet peut être affiché à la fois. Le basculement entre Engagements et Tests met à jour la vue du Calendrier en conséquence.

### Permissions

Le Calendrier respecte les permissions au niveau des objets de DefectDojo. Les Utilisateurs ne voient que les Engagements et Tests auxquels ils sont autorisés à accéder.

## Consulter et interagir avec les entrées

Au sein de chaque cellule de date, les entrées sont triées par ordre alphabétique selon le nom de l'objet. Cliquer sur une entrée redirige vers l'objet correspondant.

Le nombre d'entrées visibles chaque jour est dynamique et varie selon la taille de l'écran et le niveau de zoom du navigateur. Si le nombre d'entrées dépasse l'espace disponible dans une cellule de date, un lien au format « +X de plus » apparaît en bas de la cellule.

![image](images/OSC_ss1.png)

Cliquez sur le lien « +X de plus » pour ouvrir une fenêtre modale affichant toutes les entrées de cette date.

![image](images/OSC_ss2.png)

Il est important de noter que le Calendrier lui-même est une vue en lecture seule. Les dates doivent être modifiées dans les paramètres de l'objet Engagement ou Test lui-même.

### Logique de dénomination

La dénomination des entrées dans le Calendrier varie légèrement selon le type d'objet.

Les entrées d'Engagement incluent :
- Nom du Produit
- Nom de l'Engagement
- Responsable de test

Les entrées de Test incluent :
- Nom du Produit
- Nom de l'Engagement
- Type de Test
- Responsable de test
