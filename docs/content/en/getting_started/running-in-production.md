---
title: "Running in production"
description: "Productive use of DefectDojo needs consideration of performance and backups."
draft: false
weight: 4
---

## Production with docker-compose

The docker-compose.yml file in this repository is fully functional to evaluate DefectDojo in your local environment.

Although Docker Compose is one of the supported installation methods to deploy a containerized DefectDojo in a production environment, the docker-compose.yml file is not intended for production use without first customizing it to your particular situation.

See [Running with Docker Compose](https://github.com/DefectDojo/django-DefectDojo/blob/master/readme-docs/DOCKER.md) for more information how to run DefectDojo with Docker Compose.

### Database performance and backup

It is recommended to use a dedicated database server and not the preconfigured MySQL database. This will improve the performance of DefectDojo

In both case, if you use a dedicated database server or if you should decide to use the preconfigured MySQL database, make sure to make regular backups of the data. For a dedicated database server follow the instructions that come with the database server. For the preconfigured MySQL you can use mysqldump, e.g. as described in [How to backup a Docker MySQL database](https://dev.to/grant_bartlett/how-to-backup-a-docker-mysql-database-3nd8).

### Backup of Media files

Media files for uploaded files, including threat models and risk acceptance, are stored in a docker volume. This volume needs to be backed up regularly.

### Instance size

{{% alert title="Information" color="info" %}}
Please read the paragraphs below about key processes tweaks.
{{% /alert %}}


Having taken the database to run elsewhere, the minimum recommendation
is:

-   2 vCPUs
-   8 GB of RAM
-   2 GB of disk space (remember, your database is not here \-- so
    basically, what you have for your O/S should do). You could allocate
    a different disk than your OS\'s for potential performance
    improvements.

### Key processes

Per <https://github.com/DefectDojo/django-DefectDojo/pull/2813>, it is
now easy to somewhat improve the uWSGI and celery worker performance.

#### uWSGI

By default (except in `ptvsd` mode for debug purposes), uWSGI will
handle 4 concurrent connections.

Based on your resource settings, you can tweak:

-   `DD_UWSGI_NUM_OF_PROCESSES` for the number of spawned processes.
    (default 2)
-   `DD_UWSGI_NUM_OF_THREADS` for the number of threads in these
    processes. (default 2)

For example, you may have 4 processes with 6 threads each, yielding 24
concurrent connections.

#### Celery worker

By default, a single mono-process celery worker is spawned. This is fine
until you start having many findings, and when async operations like
deduplication start to kick in. Eventually, it will starve your
resources and crawl to a halt, while operations continue to queue up.

The following variables will help a lot, while keeping a single celery
worker container.

-   `DD_CELERY_WORKER_POOL_TYPE` will let you switch to `prefork`.
    (default `solo`)

As you\'ve enabled `prefork`, the following variables have
to be used. The default are working fairly well, see the
Dockerfile.django for in-file references.

-   `DD_CELERY_WORKER_AUTOSCALE_MIN` defaults to 2.
-   `DD_CELERY_WORKER_AUTOSCALE_MAX` defaults to 8.
-   `DD_CELERY_WORKER_CONCURRENCY` defaults to 8.
-   `DD_CELERY_WORKER_PREFETCH_MULTIPLIER` defaults to 128.

You can execute the following command to see the configuration:

`docker-compose exec celerybeat bash -c "celery -A dojo inspect stats"`
and see what is in effect.

###### Asynchronous Imports

This is an experimental features that has some [concerns](https://github.com/DefectDojo/django-DefectDojo/pull/5553#issuecomment-989679555) that need to be addressed before it can be used reliably.

Import and Re-Import can also be configured to handle uploads asynchronously to aid in 
importing especially large files. It works by batching Findings and Endpoints by a 
configurable amount. Each batch will be be processed in seperate celery tasks.

The following variables have to be used.

-   `DD_ASYNC_FINDING_IMPORT` defaults to False
-   `DD_ASYNC_FINDING_IMPORT_CHUNK_SIZE` deafults to 100

When using asynchronous imports with dynamic scanners, Endpoints will continue to "trickle" in
even after the import has returned a successful respsonse. This is becasue processing continues 
to occur after the Findings have already been imported.

To determine if an import has been fully completed, please see the progress bar in the appropriate test.

## Monitoring

To expose Django statistics for [Prometheus](https://prometheus.io/), set
`DJANGO_METRICS_ENABLED` to `True` in the settings
(see [Configuration](../configuration)).

The Prometheus endpoint is than available under the path:
`http://dd_server/django_metrics/metrics`
