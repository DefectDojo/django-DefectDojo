---
title: Configuration
description: DefectDojo est hautement configurable.
draft: false
weight: 2
audience: opensource
aliases:
- /fr/en/open_source/installation/configuration
---

## dojo/settings/settings.dist.py

Les principaux paramètres sont stockés dans [`dojo/settings/settings.dist.py`](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/settings/settings.dist.py). Il est utile d'utiliser ce fichier comme référence pour ce qui peut être configuré, mais il ne doit pas être modifié directement, car les changements seraient écrasés lors de la mise à jour de DefectDojo. Il existe plusieurs méthodes pour modifier les paramètres par défaut :

### Variables d'environnement

La plupart des paramètres peuvent être définis via des variables d'environnement.

Lorsque vous déployez DefectDojo via **Docker Compose**, vous pouvez définir des variables d'environnement dans [`docker-compose.yml`](https://github.com/DefectDojo/django-DefectDojo/blob/master/docker-compose.yml). Attention, vous devez définir les variables pour trois services : `uwsgi`, `celerybeat` et `celeryworker`.

Lorsque vous déployez DefectDojo dans un cluster **Kubernetes**, vous pouvez définir des variables d'environnement en tant que `extraConfigs` et `extraSecrets` dans [`helm/defectdojo/values.yaml`](https://github.com/DefectDojo/django-DefectDojo/blob/master/helm/defectdojo/values.yaml).

### Fichier d'environnement (hors Docker Compose ou Kubernetes)

`settings.dist.py` lit les variables d'environnement depuis un fichier dont le nom est spécifié dans la variable d'environnement `DD_ENV_PATH`. Si cette variable n'est pas définie, le fichier par défaut `.env.prod` est utilisé. Le fichier doit se trouver dans le répertoire `dojo/settings`.

Un exemple est disponible dans [`template_env`](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/settings/template-env).

### local_settings.py

`local_settings.py` peut contenir des personnalisations plus complexes, comme l'ajout d'entrées MIDDLEWARE ou INSTALLED_APP.
Ce fichier est traité *après* le traitement de settings.dist.py, ce qui vous permet de modifier les paramètres livrés par défaut avec DefectDojo.
 Le fichier doit se trouver dans le répertoire `dojo/settings`. Les variables d'environnement de ce fichier ne doivent pas avoir le préfixe `DD_`.
Si le fichier est absent, n'hésitez pas à le créer. Ne modifiez pas `settings.dist.py` directement.

Un exemple est disponible dans [`dojo/settings/template-local_settings`](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/settings/template-local_settings).

En mode release de Docker Compose, les fichiers présents dans `docker/extra_settings/` (relatif au fichier `docker-compose.yml`) seront copiés dans `dojo/settings/` au sein du conteneur docker au démarrage.

`local_settings.py` peut également être utilisé sous Kubernetes. La variable `localsettingspy` sera stockée en tant que ConfigMap et montée à l'emplacement approprié des conteneurs.

## Configuration dans l'interface

Les utilisateurs disposant du statut superuser peuvent configurer davantage d'options via l'interface, sous `Configuration` / `System Settings`.
