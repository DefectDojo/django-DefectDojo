---
title: "Architecture"
description: "The DefectDojo platform consists of several components that work together closely."
draft: false
weight: 1
---

{{ readFile "/docs/assets/svgs/DD-Architecture.svg" | safeHTML }}

## NGINX

The webserver [NGINX](https://nginx.org/en/) delivers all static content, e.g.
images, JavaScript files or CSS files.

## uWSGI

[uWSGI](https://uwsgi-docs.readthedocs.io/en/latest/) is the application server
that runs the DefectDojo platform, written in Python/Django, to serve all
dynamic content.

## Message Broker

The application server sends tasks to a [Message Broker](https://docs.celeryq.dev/en/stable/getting-started/backends-and-brokers/index.html)
for asynchronous execution. Currently, only [Redis](https://github.com/redis/redis) is supported as a broker.

## Celery Worker

Tasks like deduplication or the JIRA synchronization are performed asynchronously
in the background by the [Celery](https://docs.celeryproject.org/en/stable/)
Worker.

## Celery Beat

In order to identify and notify users about things like upcoming engagements,
DefectDojo runs scheduled tasks. These tasks are scheduled and run using Celery
Beat.

## Initializer

The Initializer setups / maintains the
database and syncs / runs migrations after version upgrades. It shuts
itself down after all tasks are performed.

## Database

The Database stores all the application data of DefectDojo. Currently only [PostgreSQL](https://www.postgresql.org/) is supported.
