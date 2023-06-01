---
title: "Architecture"
description: "The DefectDojo platform consists of several components that work together closely."
draft: false
weight: 1
---

![Architecture](../../images/DD-Architecture.svg)

## NGINX

The webserver [NGINX](https://nginx.org/en/) delivers all static content, e.g.
images, JavaScript files or CSS files.

## uWSGI

[uWSGI](https://uwsgi-docs.readthedocs.io/en/latest/) is the application server
that runs the DefectDojo platform, written in Python/Django, to serve all
dynamic content.

## Message Broker

The application server sends tasks to a [Message Broker](https://docs.celeryproject.org/en/stable/getting-started/brokers/index.html)
for asynchronous execution. [RabbitMQ](https://www.rabbitmq.com/) is a well established choice.

## Celery Worker

Tasks like deduplication or the JIRA synchonization are performed asynchronously
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

The Database stores all the application data of DefectDojo. Currently [MySQL](https://dev.mysql.com/)
and [PostgreSQL](https://www.postgresql.org/) are supported. Please note the `django-watson` search engine require one or more MyISAM tables, so you cannot use Azure MySQL or Cloud SQL for MySQL. AWS RDS MySQL supports MyISAM tables.
