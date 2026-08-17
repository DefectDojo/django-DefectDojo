---
title: Exécution en production
description: Pour une utilisation en environnement de production, il est recommandé
  d'optimiser les performances et de mettre en place des sauvegardes.
draft: false
weight: 4
audience: opensource
aliases:
- /fr/en/open_source/installation/running-in-production
---

## Utilisation en production (avec Docker compose)

Le fichier docker-compose.yml de ce dépôt est pleinement fonctionnel pour évaluer DefectDojo dans votre environnement local.

Bien que Docker Compose soit l'une des méthodes d'installation prises en charge pour déployer une instance conteneurisée de DefectDojo en environnement de production, le fichier docker-compose.yml n'est pas destiné à une utilisation en production sans être préalablement personnalisé selon votre situation particulière.

Consultez [Exécution avec Docker Compose](https://github.com/DefectDojo/django-DefectDojo/blob/master/readme-docs/DOCKER.md) pour plus d'informations sur l'exécution de DefectDojo avec Docker Compose.

### Exigences système

Il est recommandé d'utiliser un serveur de base de données dédié plutôt que la base de données PostgreSQL préconfigurée. Cela améliorera significativement les performances de DefectDojo.

#### Taille de l'instance

Avec une base de données séparée, les recommandations minimales pour exécuter DefectDojo sont :

-   2 vCPU
-   8 Go de RAM
-   10 Go d'espace disque (rappelez-vous que votre base de données n'est pas ici \-- donc
     ce que vous prévoyez pour votre O/S devrait suffire). Vous pourriez allouer
    un disque différent de celui de votre OS\'s pour des améliorations de performance
    potentielles.

### Sécurité
Vérifiez la configuration `nginx` et les autres aspects d'exécution tels que les en-têtes de sécurité, afin de vous conformer à vos exigences de conformité.
Remplacez la clé de chiffrement AES256 `&91a*agLqesc*0DJ+2*bAbsUZfR*4nLw` dans `docker-compose.yml` par une clé unique pour votre instance.
Cette clé de chiffrement est utilisée pour chiffrer les clés API et autres identifiants stockés dans Defect Dojo pour se connecter à des outils externes tels que SonarQube. Une clé peut être générée de différentes façons, par exemple à l'aide d'un gestionnaire de mots de passe ou d'`openssl` :

```
     openssl rand -base64 32
```
```
      DD_CREDENTIAL_AES_256_KEY: "${DD_CREDENTIAL_AES_256_KEY:-<PUT THE GENERATED KEY HERE>o}"
```

## Sauvegarde des fichiers

Dans les deux cas (base de données dédiée ou conteneurisée), si vous êtes en auto-hébergement, il est recommandé de mettre en place et de créer des sauvegardes périodiques de vos données.

### Fichiers multimédias

Les fichiers multimédias correspondant aux fichiers téléversés, y compris les modèles de menace et les acceptations de risque, sont stockés dans un volume docker. Ce volume doit être sauvegardé régulièrement.

## Ajustements de performance

### uWSGI

Par défaut (sauf en mode `ptvsd` à des fins de débogage), uWSGI
gère 16 connexions simultanées.

En fonction de vos paramètres de ressources, vous pouvez ajuster :

-   `DD_UWSGI_NUM_OF_PROCESSES` pour le nombre de processus créés.
    (par défaut 4)
-   `DD_UWSGI_NUM_OF_THREADS` pour le nombre de threads dans ces
    processus. (par défaut 4)

Par exemple, vous pourriez avoir 4 processus avec 6 threads chacun, ce qui donne 24
connexions simultanées.

### Celery worker

Par défaut, un seul worker celery mono-processus est créé. Lors du stockage d'un grand nombre de Constatations ou de l'exécution d'imports volumineux, il peut être utile d'ajuster ces paramètres pour éviter une pénurie de ressources.

Les variables suivantes peuvent être modifiées pour augmenter les performances du worker, tout en conservant un seul conteneur celery.

-   `DD_CELERY_WORKER_POOL_TYPE` vous permet de passer à `prefork`.
    (par défaut `solo`)

Lorsque vous activez `prefork`, les variables ci-dessous doivent
être utilisées. Consultez le fichier
Dockerfile.django-* pour les références internes.

-   `DD_CELERY_WORKER_AUTOSCALE_MIN` vaut 2 par défaut.
-   `DD_CELERY_WORKER_AUTOSCALE_MAX` vaut 8 par défaut.
-   `DD_CELERY_WORKER_CONCURRENCY` vaut 8 par défaut.
-   `DD_CELERY_WORKER_PREFETCH_MULTIPLIER` vaut 128 par défaut.

Vous pouvez exécuter la commande suivante pour voir la configuration :

`docker compose exec celerybeat bash -c "celery -A dojo inspect stats"`
et voir ce qui est en vigueur.

### Import asynchrone : obsolète
Cette fonctionnalité a été supprimée dans la version 2.47.0
