---
title: Architecture du système
description: La plateforme DefectDojo se compose de plusieurs composants qui fonctionnent
  en étroite collaboration.
draft: false
weight: 1
audience: opensource
aliases:
- /fr/en/open_source/installation/architecture
---

![image](images/dd-architecture.png)

## NGINX

Le serveur web [NGINX](https://nginx.org/en/) délivre tout le contenu statique, comme les
images, les fichiers JavaScript ou les fichiers CSS.

## uWSGI

[uWSGI](https://uwsgi-docs.readthedocs.io/en/latest/) est le serveur d'application
qui exécute la plateforme DefectDojo, écrite en Python/Django, afin de servir tout le
contenu dynamique.

## Message Broker

Le serveur d'application envoie des tâches à un [Message Broker](https://docs.celeryq.dev/en/stable/getting-started/backends-and-brokers/index.html)
pour une exécution asynchrone. Actuellement, seul [Valkey](https://valkey.io/) est pris en charge comme broker dans la configuration docker compose.
Le chart Helm utilise encore [Redis](https://github.com/redis/redis) comme broker pris en charge, mais celui-ci sera prochainement migré vers Valkey.


## Celery Worker

Les tâches telles que la déduplication ou la synchronisation JIRA sont exécutées de manière asynchrone
en arrière-plan par le Worker [Celery](https://docs.celeryproject.org/en/stable/).

## Celery Beat

Afin d'identifier et de notifier les utilisateurs à propos d'éléments tels que les engagements
à venir, DefectDojo exécute des tâches planifiées. Ces tâches sont planifiées et exécutées à l'aide de
Celery Beat.

## Initializer

L'Initializer configure/maintient la
base de données et synchronise/exécute les migrations après les mises à jour de version. Il
s'arrête automatiquement une fois toutes les tâches effectuées.

## Database

La Database stocke toutes les données applicatives de DefectDojo. Actuellement, seul [PostgreSQL](https://www.postgresql.org/) est pris en charge.
