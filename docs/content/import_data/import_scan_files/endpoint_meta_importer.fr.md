---
title: Endpoint Meta Importer
description: Appliquez en masse des étiquettes et des champs personnalisés aux points
  de terminaison via un fichier CSV
weight: 4
audience: opensource
---

L'**Endpoint Meta Importer** vous permet d'appliquer des étiquettes et des champs personnalisés à un grand nombre de points de terminaison en une seule fois, à l'aide d'un fichier CSV. Ceci est particulièrement utile pour les organisations qui effectuent des scans d'infrastructure intensifs, où les points de terminaison ont besoin de métadonnées flexibles pour le filtrage, le tri et le reporting.

## Format CSV

Le fichier CSV doit comporter une colonne `hostname` (obligatoire), ainsi qu'un nombre quelconque de colonnes supplémentaires représentant les étiquettes ou les champs personnalisés que vous souhaitez appliquer. Chaque nom de colonne supplémentaire devient la clé de l'étiquette/du champ, et la valeur de la ligne devient la valeur de l'étiquette/du champ.

**Exemple :**

```
hostname,team,public_facing
sheets.google.com,data analytics,yes
docs.google.com,language processing,yes
feedback.internal.google.com,human resources,no
```

Cela appliquerait les métadonnées suivantes :

| Point de terminaison | Étiquettes / Champs personnalisés |
|---|---|
| `sheets.google.com` | `team:data analytics`, `public_facing:yes` |
| `docs.google.com` | `team:language processing`, `public_facing:yes` |
| `feedback.internal.google.com` | `team:human resources`, `public_facing:no` |

## Prérequis

- La colonne `hostname` est **obligatoire**. Elle sert à retrouver les points de terminaison existants dont l'hôte correspond, ou à créer de nouveaux points de terminaison si aucune correspondance n'est trouvée.
- Tous les autres noms de colonnes sont traités comme des clés d'étiquette/de champ personnalisé.
- Les valeurs sont stockées au format `key:value`.

## Utiliser l'Endpoint Meta Importer

L'Endpoint Meta Importer est disponible depuis l'onglet **Points de terminaison** lors de l'affichage d'un Produit. Téléversez votre fichier CSV à cet endroit pour appliquer les métadonnées à vos points de terminaison en masse.
