---
title: Arquitectura del sistema
description: La plataforma DefectDojo consta de varios componentes que trabajan estrechamente
  entre sí.
draft: false
weight: 1
audience: opensource
aliases:
- /es/en/open_source/installation/architecture
---

![image](images/dd-architecture.png)

## NGINX

El servidor web [NGINX](https://nginx.org/en/) entrega todo el contenido estático, por ejemplo,
imágenes, archivos JavaScript o archivos CSS.

## uWSGI

[uWSGI](https://uwsgi-docs.readthedocs.io/en/latest/) es el servidor de aplicaciones
que ejecuta la plataforma DefectDojo, escrita en Python/Django, para entregar todo el
contenido dinámico.

## Bróker de mensajes

El servidor de aplicaciones envía tareas a un [bróker de mensajes](https://docs.celeryq.dev/en/stable/getting-started/backends-and-brokers/index.html)
para su ejecución asíncrona. Actualmente, solo [Valkey](https://valkey.io/) es compatible como bróker en la configuración de docker compose.
El Helm chart todavía usa [Redis](https://github.com/redis/redis) como bróker compatible, pero se migrará a Valkey próximamente.


## Celery Worker

Tareas como la deduplicación o la sincronización con JIRA se ejecutan de forma asíncrona
en segundo plano mediante el Worker de [Celery](https://docs.celeryproject.org/en/stable/).

## Celery Beat

Para identificar y notificar a los usuarios sobre eventos como los próximos Compromisos,
DefectDojo ejecuta tareas programadas. Estas tareas se programan y ejecutan mediante Celery
Beat.

## Initializer

El Initializer configura y mantiene la
base de datos, y sincroniza/ejecuta las migraciones tras las actualizaciones de versión. Se apaga
automáticamente una vez completadas todas las tareas.

## Base de datos

La base de datos almacena todos los datos de la aplicación DefectDojo. Actualmente solo se admite [PostgreSQL](https://www.postgresql.org/).
