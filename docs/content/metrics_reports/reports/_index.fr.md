---
title: Report Builder
description: Indicateurs de performance et analyses
summary: ''
date: 2026-01-20 17:33:00+00:00
lastmod: 2026-01-20 17:33:00+00:00
draft: false
weight: 2
chapter: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
exclude_search: true
---

Le Report Builder vous permet de transformer les données DefectDojo en rapports soignés et partageables — résumés exécutifs, instantanés de conformité, ensembles POA&M, détails techniques, et bien plus — destinés à des audiences internes et externes à votre équipe sécurité.

## Open source vs DefectDojo Pro

La façon de créer des rapports dépend de l'édition que vous utilisez :

| | Open Source | DefectDojo Pro |
|---|---|---|
| **Créer un rapport** | Oui — assemblage à partir de widgets | Oui — composition à partir de Blocs réutilisables |
| **Exécuter et récupérer le résultat** | Oui (HTML, impression en PDF) | Oui (PDF ou HTML enregistré) |
| **Enregistrer des Thèmes / Blocs / Modèles réutilisables** | Non — à reconstruire à chaque fois | Oui |
| **Historique persistant des rapports générés** | Non | Oui — liste, téléchargement, réexécution |
| **API REST + automatisation par LLM** | — | Oui — création → exécution → téléchargement complets |

En résumé : la version **open source** vous permet de créer un rapport, de l'exécuter et d'en exporter le résultat, mais ne sauvegarde pas les modèles ni ne conserve d'historique des rapports. **DefectDojo Pro** transforme la création de rapports en blocs réutilisables et personnalisables à votre image, que vous pouvez piloter depuis l'interface, l'API REST ou un LLM.

## Pour aller plus loin

**DefectDojo Pro**

- **[Report Builder](report-builder/)** — concepts (Thèmes, Blocs, Modèles, Rapports générés) et une présentation complète de l'interface.
- **[Automatiser les rapports avec l'API](report-builder-api/)** — créez, exécutez, interrogez et téléchargez des rapports via l'API REST, avec un script complet.
- **[Créer des rapports avec un LLM](report-builder-llm/)** — laissez un LLM concevoir, créer, exécuter et télécharger des rapports pour vous.

**Open Source**

- **[Utiliser le Report Builder](using-the-report-builder/)** — créez, exécutez et exportez un rapport avec le générateur basé sur des widgets.
