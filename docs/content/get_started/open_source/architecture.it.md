---
title: Architettura del sistema
description: La piattaforma DefectDojo è composta da diversi componenti che lavorano
  insieme in stretta collaborazione.
draft: false
weight: 1
audience: opensource
aliases:
- /it/en/open_source/installation/architecture
---

![image](images/dd-architecture.png)

## NGINX

Il webserver [NGINX](https://nginx.org/en/) distribuisce tutti i contenuti statici, ad esempio
immagini, file JavaScript o file CSS.

## uWSGI

[uWSGI](https://uwsgi-docs.readthedocs.io/en/latest/) è il server applicativo
che esegue la piattaforma DefectDojo, scritta in Python/Django, per servire tutti i
contenuti dinamici.

## Broker di messaggi

Il server applicativo invia le attività a un [Message Broker](https://docs.celeryq.dev/en/stable/getting-started/backends-and-brokers/index.html)
per l'esecuzione asincrona. Attualmente, solo [Valkey](https://valkey.io/) è supportato come broker nella configurazione docker compose.
Il chart Helm utilizza ancora [Redis](https://github.com/redis/redis) come broker supportato, ma verrà migrato a Valkey a breve.


## Celery Worker

Attività come la deduplicazione o la sincronizzazione con JIRA vengono eseguite in modo asincrono
in background dal [Celery](https://docs.celeryproject.org/en/stable/)
Worker.

## Celery Beat

Per identificare e notificare agli utenti eventi come gli engagement imminenti,
DefectDojo esegue attività pianificate. Queste attività vengono pianificate ed eseguite tramite Celery
Beat.

## Initializer

L'Initializer configura / mantiene il
database e sincronizza / esegue le migrazioni dopo gli aggiornamenti di versione. Si arresta
automaticamente al termine di tutte le attività.

## Database

Il Database memorizza tutti i dati applicativi di DefectDojo. Attualmente è supportato solo [PostgreSQL](https://www.postgresql.org/).
