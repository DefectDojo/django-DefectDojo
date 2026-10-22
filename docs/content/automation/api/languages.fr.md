---
title: Langages et lignes de code
description: Importer les données de composition des langages pour un Produit à l'aide
  de l'outil cloc
weight: 3
audience: opensource
aliases:
- /fr/en/open_source/languages
---

DefectDojo peut afficher une répartition des langages de programmation et des lignes de code pour un Produit, alimentée par l'import d'un rapport de l'outil [cloc](https://github.com/AlDanial/cloc) (Count Lines of Code) via l'API.

## Generating the cloc Report

Exécutez `cloc` sur votre base de code avec l'option `--json` pour produire un fichier JSON au format attendu :

```bash
cloc --json /path/to/your/project > cloc-report.json
```

## Importing via the API

Envoyez le rapport JSON à DefectDojo via l'API. Lors de l'import, toutes les données de langage existantes pour le Produit sont remplacées par le contenu du nouveau fichier.

L'endpoint d'import est documenté dans la [documentation de l'API DefectDojo v2](../api-v2-docs/).

## Viewing Results

Après l'import, la répartition des langages s'affiche sur le côté gauche de la page de détails du Produit, indiquant chaque langage et son nombre de lignes. Les couleurs de chaque langage sont définies par les entrées de la table `Language_Type`, préremplie avec les données de GitHub.

## Updating Language Colors

GitHub met périodiquement à jour les couleurs des langages à mesure que de nouveaux langages apparaissent. Pour récupérer les dernières données de couleurs, exécutez la commande de gestion suivante :

```bash
./manage.py import_github_languages
```

Cette commande lit les données depuis [ozh/github-colors](https://github.com/ozh/github-colors) et ajoute les nouveaux langages ou met à jour les couleurs existantes.
