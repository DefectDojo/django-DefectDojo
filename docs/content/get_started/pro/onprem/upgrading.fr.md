---
title: Mise à niveau de DefectDojo Pro (sur site)
description: Procédure de mise à niveau prise en charge pour les déploiements DefectDojo
  Pro autohébergés utilisant le chart Helm
draft: false
weight: 7
audience: pro
---

Cette page décrit la procédure de mise à niveau prise en charge pour les déploiements DefectDojo Pro autohébergés qui utilisent le chart Helm DefectDojo Pro.

## Mettez tout à niveau en une seule unité

Chaque release DefectDojo Pro se compose d'une version de chart Helm, de versions d'images de conteneurs et des fichiers de paramètres Pro. Ces éléments sont construits et testés ensemble et doivent être mis à niveau ensemble, comme une seule unité.

Mettre à niveau uniquement les tags d'image n'est pas pris en charge et cassera votre déploiement.

## Fichiers de paramètres et mises à niveau

DefectDojo Pro livre un fichier `pro_settings.py` avec chaque release, et ce fichier change à presque chaque version. Ne conservez pas d'une mise à niveau à l'autre une copie de `pro_settings.py`, et ne modifiez pas manuellement une ancienne copie. L'application doit toujours exécuter le `pro_settings.py` correspondant à sa version.

Placez vos propres personnalisations dans `local_settings.py`, jamais dans `pro_settings.py`. Votre `local_settings.py` est préservé lors des mises à niveau.

Le chart Helm fournit et monte automatiquement le `pro_settings.py` correspondant ainsi que votre `local_settings.py`. Lorsque vous effectuez la mise à niveau via le chart, il n'y a rien à copier ou à migrer manuellement.

## Procédure de mise à niveau prise en charge

1. Consultez les notes de version pour chaque version entre votre version actuelle et votre version cible, pas seulement la version cible. Consultez le [Changelog DefectDojo Pro](/releases/pro/changelog/) et les [notes de mise à niveau](/releases/os_upgrading/upgrading_guide/) spécifiques à chaque version.
2. Sauvegardez votre base de données.
3. Mettez à niveau vers la release du chart Helm correspondant à votre version d'application cible, en réutilisant vos fichiers de valeurs existants. Ne modifiez pas les tags d'image indépendamment de la version du chart.

Si vous avez des questions concernant la mise à niveau de votre déploiement sur site, contactez [support@defectdojo.com](mailto:support@defectdojo.com).
