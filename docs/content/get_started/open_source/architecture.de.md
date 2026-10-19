---
title: Systemarchitektur
description: Die DefectDojo-Plattform besteht aus mehreren Komponenten, die eng zusammenarbeiten.
draft: false
weight: 1
audience: opensource
aliases:
- /en/open_source/installation/architecture
---

![image](images/dd-architecture.png)

## NGINX

Der Webserver [NGINX](https://nginx.org/en/) liefert alle statischen Inhalte aus, zum Beispiel
Bilder, JavaScript-Dateien oder CSS-Dateien.

## uWSGI

[uWSGI](https://uwsgi-docs.readthedocs.io/en/latest/) ist der Anwendungsserver,
der die in Python/Django geschriebene DefectDojo-Plattform ausführt und alle
dynamischen Inhalte bereitstellt.

## Message Broker

Der Anwendungsserver übergibt Aufgaben an einen [Message Broker](https://docs.celeryq.dev/en/stable/getting-started/backends-and-brokers/index.html)
zur asynchronen Ausführung. Im Docker-Compose-Setup wird derzeit nur [Valkey](https://valkey.io/) als Broker unterstützt.
Das Helm-Chart nutzt weiterhin [Redis](https://github.com/redis/redis) als Broker, wird aber in Kürze auf Valkey umgestellt.


## Celery Worker

Aufgaben wie die Deduplizierung oder die JIRA-Synchronisierung werden asynchron
im Hintergrund vom [Celery](https://docs.celeryproject.org/en/stable/)
Worker ausgeführt.

## Celery Beat

Um Benutzer zum Beispiel über anstehende Engagements zu informieren,
führt DefectDojo geplante Aufgaben aus. Diese Aufgaben werden mit Celery
Beat geplant und ausgeführt.

## Initializer

Der Initializer richtet die Datenbank ein, pflegt sie und
führt nach Versions-Upgrades die Migrationen aus. Er beendet sich
selbst, sobald alle Aufgaben erledigt sind.

## Datenbank

Die Datenbank speichert alle Anwendungsdaten von DefectDojo. Derzeit wird nur [PostgreSQL](https://www.postgresql.org/) unterstützt.
